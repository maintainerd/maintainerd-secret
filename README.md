# maintainerd-secret

maintainerd's **own** secret manager — a first-party vault, never a facade over
anyone else's. Vault / AWS Secrets Manager / Azure Key Vault / GCP SM are
*alternative providers an operator may choose instead of this service*; this service
never proxies to them.

It runs **standalone** — an organization can adopt just this plus maintainerd-auth —
or **ecosystem-attached**, where Core calls `Setup` to register as controller and
system-Auth (IAM) governs access.

Built on the kit (`github.com/maintainerd/kit`) for shared config, logging and the
HTTP+gRPC server, so it repeats no scaffolding.

## Storage engine

Postgres-backed. A restart loses nothing.

```
tenants → projects → environments → folders (hierarchical) → secrets → secret_versions
```

- **tenants** mirror Auth's tenants (`auth_tenant_uuid`); Auth owns identity, this
  service owns encrypted material. The same split Core makes.
- **environments** are first-class (dev/staging/prod), because that is the level real
  grants are written at, and the same key name is expected to exist once per
  environment.
- **folders** are an adjacency list plus a **materialized absolute path**, so prefix
  listing and MRN resource paths are one indexed comparison rather than a recursive
  walk. A move rewrites the subtree's paths and the MRNs derived from them, in one
  transaction.
- **secrets** hold identity and metadata only. There is no value column: payloads
  live exclusively in `secret_versions`, which is why a listing structurally cannot
  leak one.
- **secret_versions** are append-only, enforced by a database trigger. Every write
  appends; nothing rewrites history.

## Encryption — envelope, AES-256-GCM

Every version gets its **own DEK**. The DEK encrypts the payload; a **root key
(KEK)** encrypts the DEK and never touches a payload.

- The payload is sealed with AES-256-GCM under a random 12-byte nonce, with
  `(tenant UUID, secret UUID, version)` bound as **AAD** — so a ciphertext copied
  into a different secret's row fails authentication instead of decrypting into the
  wrong place. The AAD binds *immutable* coordinates on purpose: binding the folder
  path would mean an administrative folder move silently destroyed every value
  beneath it.
- **Rotating the root key re-wraps DEKs and never rewrites ciphertext** — that is the
  whole point. `RewrapAll` is batched, resumable and idempotent; the old key is
  retired only once a `COUNT` proves no version still references it.
- **`checksum`** is SHA-256 of the plaintext, stored so "did this value change?" and
  "is this row intact?" are answerable without the root key. A write whose checksum
  matches the current version creates **no new version** — which is what stops a
  rotation loop from inflating history.
- Plaintexts and DEKs are zeroized after use, and a decrypted value is a
  `crypto.Plaintext`, which renders as `[REDACTED]` through `String`, `%v`, `slog`
  and `json.Marshal`. No error in this service carries a value, a DEK, or a root key.

### Root of trust

The key always comes from **outside** the database — a store cannot unlock itself.

| Provider | Status | Notes |
|---|---|---|
| `env` | built | 32 bytes from `SECRET_ROOT_KEY`, hex or base64, validated |
| `file` | built | sealed key file; **refuses** a group/world-readable file |
| `aws_kms` `gcp_kms` `azure_kv` | registered, not built | the interface is the seam; config for them validates today, construction fails with a clear message |

**Outside `APP_ENV=development` a missing or malformed root key is a boot error** —
never a silently generated one. A generated key makes every secret written before the
next restart permanently undecryptable, and the failure is invisible until it is far
too late.

## Lifecycle

- **Versioning** — every write appends; get-latest, get-by-version, configurable
  retention (`KeepVersions`, per secret or service-wide). Pruning deletes the oldest
  through a sanctioned transaction-local GUC and **never** the current version.
- **Soft delete + recovery window** — delete schedules destruction (`destroy_after`)
  and destroys nothing. Restore brings the secret back with its full history. Hard
  destroy is refused inside the window by the SQL itself, compared against the
  database's own clock.
- **Audit** — append-only, and it **records reads**. `secret.read` and
  `secret.reveal` are distinct actions, because metadata access and value access are
  different grants.
- **Durable one-shot setup lock** — `setup_state` in the database, not process
  memory. The prototype's in-memory lock reopened the setup window on every restart.
- **No cross-tenant reads** — `tenant_id` is in the `WHERE` clause of every secret
  query, so sqlc will not compile a call that omits it.

## Owns

`maintainerd.secret.v1.SecretService` (gRPC `:9092`): `Ping · Setup · Put · Get ·
List · Delete`. The flat key is mapped onto the real hierarchy
(`db/primary/password` → folder `/db/primary`, key `password`), so a secret written
through it is an ordinary secret. The hierarchical API, authorization middleware and
console are the next wave.

## Run

```bash
export DB_HOST=localhost DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=maintainerd_secret
export SECRET_ROOT_KEY=$(openssl rand -hex 32)
make run

grpcurl -plaintext localhost:9092 maintainerd.secret.v1.SecretService/Ping
curl localhost:8092/healthz
```

Migrations are embedded and applied on boot. `make check` runs the full local gate
(gofmt, vet, staticcheck, tests); `make sqlc` regenerates `internal/storage` from the
migrations and queries.

> **Migrations are create-only.** One create file per table, edited in place while the
> schema is under development — never an `ALTER` migration. Development databases are
> recreated rather than migrated forward. A test enforces this.

## Config (env)

### App
| Var | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `development` enables the ephemeral key and an open setup window; any other value fails closed |
| `LOG_LEVEL` | `info` | `debug`\|`info`\|`warn`\|`error` |
| `GRPC_PORT` | `9092` | SecretService gRPC |
| `HTTP_PORT` | `8092` | HTTP liveness |

### Database (host/port/user/password/name required)
| Var | Default | Purpose |
|---|---|---|
| `DB_HOST` `DB_PORT` `DB_USER` `DB_PASSWORD` `DB_NAME` | — | connection; never logged |
| `DB_SSLMODE` | `disable` | `disable` is refused outside development |
| `DB_MAX_OPEN_CONNS` | `25` | pool ceiling |
| `DB_MAX_IDLE_CONNS` | `5` | pool floor; must not exceed the ceiling |
| `DB_CONN_MAX_LIFETIME_SEC` | `300` | connection lifetime |
| `DB_STATEMENT_TIMEOUT_MS` | `30000` | server-side statement timeout |

### Root of trust
| Var | Default | Purpose |
|---|---|---|
| `SECRET_ROOT_KEY_PROVIDER` | `env` | `env`\|`file`\|`aws_kms`\|`gcp_kms`\|`azure_kv` |
| `SECRET_ROOT_KEY` | — | 32-byte AES-256 KEK as hex or base64. **Required outside development.** Never log it |
| `SECRET_ROOT_KEY_FILE` | — | sealed key file for the `file` provider; must be `0600` |

### Store policy
| Var | Default | Purpose |
|---|---|---|
| `SECRET_KEEP_VERSIONS` | `10` | default versions retained per secret (min 1) |
| `SECRET_RECOVERY_WINDOW` | `720h` | how long a deleted secret stays restorable; `0` refused outside development |
| `SECRET_REWRAP_BATCH_SIZE` | `500` | versions re-wrapped per rotation query |

### Setup and default scope
| Var | Default | Purpose |
|---|---|---|
| `SETUP_BOOTSTRAP_TOKEN` | — | gates the one-time `Setup`. **Required outside development**; never log it |
| `SECRET_DEFAULT_SCOPE_AUTOCREATE` | `true` | create the default tenant/project/environment on boot |
| `SECRET_DEFAULT_TENANT` | `default` | the scope the flat-key RPCs address |
| `SECRET_DEFAULT_PROJECT` | `default` | " |
| `SECRET_DEFAULT_ENVIRONMENT` | `default` | " |

A malformed numeric or boolean value is a **boot error**, not a silent fallback to the
default — a typo in a retention setting is a configuration change nobody made.
