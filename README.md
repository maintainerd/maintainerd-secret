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

**gRPC `:9092`** — `maintainerd.secret.v1.SecretService`: `Ping · Setup · Put · Get ·
List · Delete`. The flat key is mapped onto the real hierarchy
(`db/primary/password` → folder `/db/primary`, key `password`), so a secret written
through it is an ordinary secret.

**REST `:8092`** — the hierarchical API under `/api/v1`, plus an unguarded
`/healthz`. Segments are **flat** (`/projects`, `/environments`, `/folders`,
`/secrets`, `/bulk`, `/imports`, `/webhooks`, `/audit`, `/setup`) rather than nested,
which is what makes the guard's per-segment permission allowlist meaningful: an
unmapped segment is denied even to a valid token.

Reveal and batch-get are **POSTs despite being reads**. A secret's address in a URL
ends up in access logs, proxy logs, browser history and referer headers; a body does
not. The permission required is still the read one — the HTTP verb is a transport
detail and the privilege is not.

### Authorization

Two layers, answering different questions. The **surface guard** verifies the bearer
token (Auth's JWKS + issuer + audience) and checks the segment's baseline permission;
the **operation check** decides whether *this* principal may perform *this* action on
*this* MRN. Both are required — layer 1 alone is a vault where anyone who may read one
secret may read all of them.

Permissions: `secret:ReadMetadata · GetSecret · PutSecret · DeleteSecret ·
RotateSecret · ListSecrets · ManageProject · ManageEnvironment · ManageFolder ·
ManageRotation · ReadAudit · Admin`. `ReadMetadata` and `GetSecret` are deliberately
**different grants**: browsing what exists is what an engineer needs to operate a
system; revealing a value is seeing the production database password.

Outside `APP_ENV=development` a missing auth configuration does **not** degrade to
open — REST answers 503 and gRPC serves health only.

## Console

The vault ships **its own console** at **`console.secret.maintainerd.local`**, in
[`web/console`](web/console). Because maintainerd-secret is adoptable alone, its
dashboard is a first-class SPA rather than a page inside maintainerd's core console.

React 19 + Vite + TypeScript + Tailwind + Radix, authenticating with OAuth2
authorization code + PKCE against maintainerd-auth and calling this service's
`/api/v1` with the resulting bearer token. It holds no token in storage, never
fetches a value for a list, and keeps a secret's address out of every URL. See
[`web/console/README.md`](web/console/README.md) for its environment, the OAuth
client it expects, and how to run it.

## Run

### Locally

```bash
export DB_HOST=localhost DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=maintainerd_secret
export SECRET_ROOT_KEY=$(openssl rand -hex 32)
make run

grpcurl -plaintext localhost:9092 maintainerd.secret.v1.SecretService/Ping
curl localhost:8092/healthz
curl localhost:8092/api/v1/setup/status
```

### In the dev stack

`maintainerd-dev` runs the service (`m9d-secret`), its Postgres (`m9d-secret-db`)
and its console (`m9d-secret-console`) under the `maintainerd`, `all` and
`all-observed` profiles:

```bash
cd ../maintainerd-dev
./maintainerd up --profile=all -d
```

- Console: **https://console.secret.maintainerd.local** (nginx also proxies `/api/`
  there to `m9d-secret:8092`, so the SPA is same-origin)
- API direct: **https://console-api.secret.maintainerd.local**

The dev service runs with `APP_ENV=development` and no `AUTH_*` variables, so the
guard is **development-open** and the console talks to it without a token, saying so
in a permanent banner. Set `MAINTAINERD_SECRET_AUTH_JWKS_URL`, `..._AUTH_ISSUER` and
`..._AUTH_AUDIENCE` to exercise real enforcement.

First run lands on the setup wizard; the dev bootstrap token is `devtoken`.

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

### Authorization (all three together, or none)
| Var | Default | Purpose |
|---|---|---|
| `AUTH_JWKS_URL` | — | maintainerd-auth's JWKS endpoint — where token-verifying keys come from |
| `AUTH_ISSUER` | — | the `iss` a token must carry |
| `AUTH_AUDIENCE` | — | the `aud` a token must carry: this service's resource-API identifier in Auth |

A **partial** set is a boot error. A JWKS URL without an issuer and audience check
accepts any token Auth ever signed, including tokens minted for a different service.
With none set, the API is disabled outside development (503 / health-only gRPC); in
development it opens with a loud boot banner naming every guard that is off.

### References, rotation and webhooks
| Var | Default | Purpose |
|---|---|---|
| `SECRET_REFERENCE_MAX_DEPTH` | `8` | backstop on reference-chain depth; cycles are detected precisely, not merely bounded |
| `SECRET_ROTATION_ENABLED` | `true` | runs the background rotator. Turning it off **preserves every policy** |
| `SECRET_ROTATION_INTERVAL` | `5m` | how often the rotator scans for due secrets |
| `SECRET_ROTATION_BATCH` | `50` | secrets rotated per pass |
| `SECRET_WEBHOOKS_ENABLED` | `true` | deliver change/rotation notifications. A delivery never carries a value |
| `SECRET_WEBHOOK_CONCURRENCY` | `4` | parallel deliveries per event |

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
