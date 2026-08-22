# maintainerd-secret

maintainerd's **own** secret manager — a first-party vault, never a facade over
anyone else's. Vault / AWS Secrets Manager / Azure Key Vault / GCP SM are
*alternative providers an operator may choose instead of this service*; this service
never proxies to them.

It runs in one of **two modes**, selected by `MAINTAINERD_MODE`:

| Mode | Value | What it means |
|---|---|---|
| **Standalone** *(default)* | `standalone` | You run **auth + secret and nothing else**. There is no maintainerd-core anywhere. You create this service's identity by hand in Auth's console and hand it over as environment variables. |
| **Core-attached** | `core` | maintainerd-core provisions this service through its setup gRPC surface and records itself as controller. |

**Standalone is the default, and it is a first-class way to run this service** — not
a fallback. A developer who never adopts core gets a fully enforcing vault by doing
nothing but following the runbook below. See **[Run modes](#run-modes)**.

In neither mode does this service manage authentication. **maintainerd-auth mints
tokens and owns principals, roles and grants; this service only enforces the
permissions a token carries.** The mode decides how it learns which Auth to trust,
not whether it trusts one.

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

**Permission checking is the SDK's job.** Every route and every RPC is guarded
through `github.com/maintainerd/sdk/authz` — the shared enforcement point every
maintainerd service and third-party resource server uses. This repo contributes only
its *vocabulary*: the `secret:` permission constants, the route table, the gRPC
method table and the exemption set, expressed as one `authz.Map` in
[`internal/platform/permissions`](internal/platform/permissions/permissions.go).
There is no hand-rolled authorization code here any more.

Two layers, answering different questions. The **surface guard** verifies the bearer
token (Auth's JWKS + issuer + audience) and checks the surface's baseline permission;
the **operation check** decides whether *this* principal may perform *this* action on
*this* MRN. Both are required — layer 1 alone is a vault where anyone who may read one
secret may read all of them.

The route/method table **is the allowlist**: an unmapped surface is denied even to a
valid token, so mounting a route or registering an RPC without deciding its permission
fails closed instead of shipping open. A test walks the live chi router and the live
gRPC service descriptors and fails if either grows a surface the table does not
account for — see [The gap audit](#the-gap-audit).

#### Permissions

| Permission | Grants |
|---|---|
| `secret:ReadMetadata` | list and describe secrets and the hierarchy. **Never returns a value.** |
| `secret:GetSecret` | **reveal** — read a decrypted value. Individually audited; re-checked at every reference hop. |
| `secret:PutSecret` | write a value (create the secret, or append a version) |
| `secret:DeleteSecret` | soft-delete, restore, destroy |
| `secret:RotateSecret` | rotate a value on demand |
| `secret:ListSecrets` | list a scope (metadata only) |
| `secret:ManageProject` | create/update/delete projects |
| `secret:ManageEnvironment` | create/update/delete environments |
| `secret:ManageFolder` | create/move/delete folders, and manage scope imports |
| `secret:ManageRotation` | rotation policies and webhook endpoints |
| `secret:ReadAudit` | read the access trail |
| `secret:Admin` | blanket. Implies every permission above; does **not** widen resource scope |

`ReadMetadata` and `GetSecret` are deliberately **different grants**: browsing what
exists is what an engineer needs to operate a system; revealing a value is seeing the
production database password. Collapsing them would mean every principal who can
render a console page can also exfiltrate every credential on it.

#### REST routes → permission

Keyed by the first path segment under `/api/v1`. `GET`/`HEAD` require the read
permission; every other verb requires the write one.

| Segment | Read (`GET`/`HEAD`) | Write (everything else) |
|---|---|---|
| `/projects` | `secret:ReadMetadata` | `secret:ManageProject` |
| `/environments` | `secret:ReadMetadata` | `secret:ManageEnvironment` |
| `/folders` | `secret:ReadMetadata` | `secret:ManageFolder` |
| `/imports` | `secret:ReadMetadata` | `secret:ManageFolder` |
| `/secrets` | `secret:ReadMetadata` | `secret:ReadMetadata` † |
| `/bulk` | `secret:ReadMetadata` | `secret:ReadMetadata` † |
| `/webhooks` | `secret:ReadMetadata` | `secret:ManageRotation` |
| `/audit` | `secret:ReadAudit` | `secret:Admin` |
| `/setup` | *exempt* ‡ | *exempt* ‡ |
| `/healthz`, `/readyz` | *exempt* ‡ | — |

† **Both verbs carry the metadata baseline on purpose.** Several routes on those
segments are reads carried by a `POST` (reveal takes a body so a secret address never
lands in an access log; batch get likewise), so a verb-derived split would demand a
write permission for a read. The real privilege — `GetSecret` to reveal, `PutSecret`
to write, `DeleteSecret` to delete — is enforced **per operation against the target's
MRN** in `internal/api`, which is the only place it can be enforced correctly anyway.
Those permissions are still *declared*, so Auth registers them.

‡ See [Exemptions](#exemptions).

#### gRPC methods → permission

`maintainerd.secret.v1.SecretService`:

| Method | Permission |
|---|---|
| `Put` | `secret:PutSecret` |
| `Get` | `secret:GetSecret` *(the legacy flat Get is a reveal)* |
| `List` | `secret:ListSecrets` |
| `Delete` | `secret:DeleteSecret` |
| `CreateProject` · `UpdateProject` · `DeleteProject` | `secret:ManageProject` |
| `ListProjects` · `GetProject` | `secret:ReadMetadata` |
| `CreateEnvironment` · `UpdateEnvironment` · `DeleteEnvironment` | `secret:ManageEnvironment` |
| `ListEnvironments` · `GetEnvironment` | `secret:ReadMetadata` |
| `CreateFolder` · `MoveFolder` · `DeleteFolder` | `secret:ManageFolder` |
| `ListFolders` | `secret:ReadMetadata` |
| `CreateImport` · `UpdateImport` · `DeleteImport` | `secret:ManageFolder` |
| `ListImports` | `secret:ReadMetadata` |
| `GetSecret` | `secret:GetSecret` |
| `DescribeSecret` · `ListSecretVersions` | `secret:ReadMetadata` |
| `ListSecrets` · `ListDeletedSecrets` | `secret:ListSecrets` |
| `PutSecret` · `UpdateSecretMetadata` · `RollbackSecret` | `secret:PutSecret` |
| `RotateSecret` | `secret:RotateSecret` |
| `SetRotationPolicy` | `secret:ManageRotation` |
| `DeleteSecret` · `RestoreSecret` · `DestroySecret` | `secret:DeleteSecret` |
| `BatchGetSecrets` · `BatchPutSecrets` | `secret:ReadMetadata` † |
| `CreateWebhookEndpoint` · `UpdateWebhookEndpoint` · `DeleteWebhookEndpoint` | `secret:ManageRotation` |
| `ListWebhookEndpoints` · `ListWebhookDeliveries` | `secret:ReadMetadata` |
| `ListAuditEvents` | `secret:ReadAudit` |
| `Ping` · `Setup` | *exempt* ‡ |

`maintainerd.secret.v1.SetupService` — `GetSetupStatus` · `Setup` · `CompleteSetup` —
is *exempt* ‡.

#### Exemptions

Exactly ten surfaces are served with **no permission check**, and every one carries
its own gate:

| Surface | Why it cannot be token-guarded | What guards it instead |
|---|---|---|
| `GET /healthz` | an orchestrator must probe before it holds a credential | discloses the literal string `ok` |
| `GET /readyz` | same | discloses a dependency *name* (`database`, `auth`) — never an address, driver message or version |
| `/api/v1/setup` (+ `/status`) | provisioning is what makes tokens mintable at all, so it must work **before** Auth exists | `SETUP_BOOTSTRAP_TOKEN` compared in constant time, rate-limited per client IP, and refused entirely once an orchestrator owns the instance (or `MAINTAINERD_MODE=core` declares one will). Anonymous status returns **one bit**. |
| `grpc.health.v1.Health/Check` · `/Watch` | as `/healthz` | the standard health protocol leaks nothing beyond "serving" |
| `SecretService/Ping` | an orchestrator has to ask "is this provisioned yet" before provisioning the thing that mints tokens | answers `{ok, setup_complete}` and nothing else |
| `SecretService/Setup` | the legacy flat-surface first-run RPC | bootstrap token, constant-time compare |
| `SetupService/GetSetupStatus` · `/Setup` · `/CompleteSetup` | the controlled first-run surface | `x-setup-token` metadata header, constant-time compare; the full status payload additionally needs the token or `secret:Admin` |

Exemptions are matched **exactly** for gRPC (never by service prefix) and on a
**segment boundary** for HTTP, so a new RPC on `SetupService` — or a route named
`/api/v1/setup-admin` — fails closed rather than inheriting a neighbour's exemption.

**Server reflection is neither mapped nor exempt.** That combination is deliberate:
it makes reflection reachable only in development-open mode, where the guard admits
every caller before it consults the table. Reflection enumerates every RPC and message
— useful with `grpcurl` on a laptop, a map of the vault's API in production. The
bootstrap additionally registers it only in development.

#### Fail-closed startup

Outside `APP_ENV=development` a missing auth configuration does **not** degrade to
open — every guarded surface answers `503` / `codes.Unavailable`, `/readyz` reports
not-ready, and the probes plus the self-guarded setup surface stay reachable so the
instance can still be provisioned. In development it opens with a loud boot banner
naming every guard that is off. In **standalone** mode outside development, an
incomplete configuration is a **boot error naming exactly what to set** rather than a
service that starts and answers 503 to everything.

#### The gap audit

`internal/platform/permissions/audit_test.go` is the test that keeps "no gaps" true
tomorrow rather than only today. It:

1. builds the **real chi router** this service mounts and walks it with `chi.Walk`;
2. flattens the **generated `grpc.ServiceDesc` values** `grpc.Server` dispatches on —
   unary methods *and* streams;
3. requires every one to be either mapped to a **non-empty** permission or covered by
   an exemption that has a **written justification** in the test file;
4. checks the reverse direction — no mapped segment or method that nothing serves;
5. checks itself for vacuity, by requiring surfaces that do *not* exist to read as
   gaps.

Both lists are derived from the live surface, never hand-kept, because a hand-kept
list drifts silently and a test that has stopped reading the surface is worse than no
test: it reports "no gaps" with confidence.

## Run modes

`MAINTAINERD_MODE` selects one of two worlds. They differ in **who creates this
service's identity in Auth**, and therefore in what has to be in the environment
before the process can enforce anything.

### Standalone — `MAINTAINERD_MODE=standalone` (default)

There is no maintainerd-core anywhere. maintainerd-auth is already running and set
up. **You create this service's identity by hand, in Auth's own console, and hand it
to secret as environment variables.** Nothing about core is involved or required.

The REST setup wizard (`POST /api/v1/setup`) is the bootstrap path, and because Auth
already exists, setup here only creates secret's **own tenant mirror, default project
and default environment** — it does not create anything in Auth.

#### The manual steps, in order

Do all of this in **maintainerd-auth's console**, before starting secret.

1. **Create the service principal** for secret. This is the identity Auth knows the
   vault by. Note its tenant.

2. **Create the resource API** for secret and give it an **identifier** — for example
   `maintainerd-secret`. This identifier is the `aud` claim secret will demand, so
   write it down: it becomes `AUTH_AUDIENCE`.

3. **Register the permissions** on that resource API. Register **exactly** these
   twelve, spelled exactly like this:

   ```
   secret:ReadMetadata      secret:GetSecret         secret:PutSecret
   secret:DeleteSecret      secret:RotateSecret      secret:ListSecrets
   secret:ManageProject     secret:ManageEnvironment secret:ManageFolder
   secret:ManageRotation    secret:ReadAudit         secret:Admin
   ```

   The list is not decorative and it is not a superset to trim. Secret's guard demands
   these strings; a permission that exists in the guard and not in Auth can never be
   carried by any token, so **every call using it answers 403 regardless of who makes
   it, with nothing in any log saying why.** A running instance reports the same list
   at `GET /api/v1/setup/status` (with the setup token or `secret:Admin`), derived from
   the code that enforces it — check against that rather than against this README if
   they ever disagree.

4. **Create the backend m2m client** — confidential, `client_credentials` — for the
   secret service itself, and grant it the permissions it needs. Keep its **client id**
   and either its **client secret** or its **private key**, depending on which client
   authentication method you chose. → `SECRET_CLIENT_ID` and one of
   `SECRET_CLIENT_SECRET` / `SECRET_CLIENT_PRIVATE_KEY_FILE`.

5. **Create the frontend SPA client** for secret's console — public,
   `authorization_code` with PKCE (`S256`) **required**, no client secret — with:
   - redirect URI `https://<console-host>/auth/callback`
   - post-logout redirect URI `https://<console-host>`
   - scopes `openid profile email`
   - audience = the resource-API identifier from step 2

   Keep its **client id**. → `SECRET_CONSOLE_CLIENT_ID`.

6. **Note Auth's issuer and JWKS URL.** → `AUTH_ISSUER`, `AUTH_JWKS_URL`.

7. **Grant your operators permissions** on the resource API. What a signed-in user can
   do in the console comes from their grants in Auth, not from what the console asks
   for. Start people on `secret:ReadMetadata` and add `secret:GetSecret` deliberately —
   they are separate grants precisely so that reveal is a decision.

8. **Start secret** with the variables below, then open the console and run the
   first-run wizard.

Missing any of `AUTH_ISSUER`, `AUTH_JWKS_URL`, `AUTH_AUDIENCE`, `SECRET_CLIENT_ID`,
`SECRET_CLIENT_SECRET`-or-`SECRET_CLIENT_PRIVATE_KEY_FILE`, or
`SECRET_CONSOLE_CLIENT_ID` outside `APP_ENV=development` is a **boot error naming
exactly what to set**, all of them at once — not a silent degrade and not one restart
per missing variable. In development, missing configuration degrades to the dev-open
guard with its loud banner, unchanged.

#### Worked example

```bash
# --- what you created in Auth, steps 1-6 ------------------------------------
export MAINTAINERD_MODE=standalone                # the default; set it anyway, explicitly
export AUTH_ISSUER=https://identity.auth.example/
export AUTH_JWKS_URL=https://identity-api.auth.example/.well-known/jwks.json
export AUTH_AUDIENCE=maintainerd-secret           # the resource-API identifier (step 2)

export SECRET_CLIENT_ID=secret-backend            # backend m2m client (step 4)
export SECRET_CLIENT_SECRET=...                   # or SECRET_CLIENT_PRIVATE_KEY_FILE=/run/secrets/secret-client.pem
export SECRET_CONSOLE_CLIENT_ID=secret-console    # frontend SPA client (step 5)

# --- this service's own configuration ---------------------------------------
export APP_ENV=production
export DB_HOST=... DB_PORT=5432 DB_USER=... DB_PASSWORD=... DB_NAME=maintainerd_secret
export DB_SSLMODE=require
export SECRET_ROOT_KEY=$(openssl rand -hex 32)    # store this OUTSIDE the database
export SETUP_BOOTSTRAP_TOKEN=$(openssl rand -hex 24)

./bin/secretd
```

The boot log states the mode and, in standalone, exactly which Auth it is enforcing
against:

```
INFO starting maintainerd-secret app_env=production mode="standalone (an operator provisions this instance; auth is configured by environment)" ...
INFO run mode: standalone auth_issuer=https://identity.auth.example/ auth_audience=maintainerd-secret client_id=secret-backend client_auth=client_secret console_client_id=secret-console
INFO authorization: ENFORCED service=secret mode=enforced permissions="secret:Admin secret:DeleteSecret secret:GetSecret ..."
```

Neither the client secret nor the private-key path is ever logged. The issuer and the
audience are — they appear in every token this service verifies, and they are the two
values most often subtly wrong (a trailing slash, or the resource API's *name* instead
of its *identifier*).

Then provision the instance:

```bash
curl -X POST https://secret.example/api/v1/setup \
  -H "X-Setup-Token: $SETUP_BOOTSTRAP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"controller":"ops@example.com","tenant":"acme","project":"platform","environment":"prod"}'
```

Point the console's runtime config at the same values — the console reads
`SECRET_CONSOLE_CLIENT_ID`, `AUTH_ISSUER` and `AUTH_AUDIENCE` by those exact names, so
there is one value per concept and no way for the two halves to disagree. See
[`web/console/README.md`](web/console/README.md#rendering-configjs-for-a-deployment).

### Core-attached — `MAINTAINERD_MODE=core`

Unchanged from before. maintainerd-core provisions the service principal, the resource
API, the permissions and both clients from its templates, drives the gRPC
`SetupService`, and records itself as this instance's controller.

None of the standalone credentials are required here — they are core's to provision —
so booting before core has run is normal, expected, and warned about rather than
refused. The API answers 503 until it happens.

**The REST setup wizard refuses from the first boot in this mode**, with
`setup_orchestrated`. Two open first-run paths is a race whose winner owns the vault,
and the REST one is reachable by anything on the network; declaring the mode closes
that window instead of relying on the controller to win it. In standalone mode the
wizard behaves exactly as it always has: open until an orchestrator actually owns the
instance, which is what keeps an instance that starts standalone and is later adopted
by core provisionable.

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
in a permanent banner. That is the sanctioned development degrade: standalone is still
the mode, and an incomplete identity configuration is warned about rather than
refused. Set `MAINTAINERD_SECRET_AUTH_JWKS_URL`, `..._AUTH_ISSUER` and
`..._AUTH_AUDIENCE` to exercise real enforcement.

First run lands on the setup wizard; the dev bootstrap token is `devtoken`.

Migrations are embedded and applied on boot. `make check` runs the full local gate
(gofmt, vet, staticcheck, tests); `make sqlc` regenerates `internal/storage` from the
migrations and queries.

> **Migrations are create-only.** One create file per table, edited in place while the
> schema is under development — never an `ALTER` migration. Development databases are
> recreated rather than migrated forward. A test enforces this.

## Config (env)

Every variable below is listed with its default. Which ones are **required** depends
on the run mode — see the two mode tables immediately after *App*.

### App
| Var | Default | Purpose |
|---|---|---|
| `MAINTAINERD_MODE` | `standalone` | `standalone`\|`core`. Selects who provisions this service's identity in Auth. An unrecognised value is a boot error naming both |
| `APP_ENV` | `development` | `development` enables the ephemeral key and an open setup window; any other value fails closed |
| `LOG_LEVEL` | `info` | `debug`\|`info`\|`warn`\|`error` |
| `GRPC_PORT` | `9092` | SecretService gRPC |
| `HTTP_PORT` | `8092` | HTTP liveness |

### Required in `MAINTAINERD_MODE=standalone` (outside development)

You create every one of these by hand in Auth's console — see
[the runbook](#the-manual-steps-in-order). Missing any of them is a boot error naming
all of them at once.

| Var | Default | Purpose |
|---|---|---|
| `AUTH_ISSUER` | — | the `iss` a token must carry. Auth's hosted identity origin |
| `AUTH_JWKS_URL` | — | maintainerd-auth's JWKS endpoint — where token-verifying keys come from |
| `AUTH_AUDIENCE` | — | the `aud` a token must carry: this service's **resource-API identifier** in Auth |
| `SECRET_CLIENT_ID` | — | this service's own **backend m2m** client id in Auth |
| `SECRET_CLIENT_SECRET` | — | that client's secret. **Never log it, never put it in the console's `config.js`.** Exactly one of this or the private key |
| `SECRET_CLIENT_PRIVATE_KEY_FILE` | — | path to a private key for `private_key_jwt` client authentication — stronger, because the credential never leaves the host. Setting both this and `SECRET_CLIENT_SECRET` is a boot error |
| `SECRET_CONSOLE_CLIENT_ID` | — | the console's **public SPA** client id. Not a credential (it is published in the browser), but required: a console pointed at a client id that does not exist sends the operator to an error they cannot act on. The console reads this same variable name |

### Required in `MAINTAINERD_MODE=core`

**None of the above.** maintainerd-core provisions all of it and supplies the values;
booting before that has happened is the normal pre-provisioning state and is warned
about, not refused. The API answers 503 in the meantime.

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

`AUTH_JWKS_URL` · `AUTH_ISSUER` · `AUTH_AUDIENCE` — described in the standalone table
above.

A **partial** set is a boot error in either mode. A JWKS URL without an issuer and
audience check accepts any token Auth ever signed, including tokens minted for a
different service, so a partial configuration is treated as no configuration.

With **none** set:

- `MAINTAINERD_MODE=standalone`, outside development → **boot error** naming what to
  set. Standalone means you own this wiring; missing it is a mistake, not a choice.
- `MAINTAINERD_MODE=core`, outside development → boots with a warning. Core has not
  provisioned the instance yet; the API answers 503 and gRPC serves health only until
  it does.
- `APP_ENV=development`, either mode → opens with a loud boot banner naming every
  guard that is off.

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
| `SETUP_BOOTSTRAP_TOKEN` | — | gates **both** first-run surfaces: the REST wizard (`X-Setup-Token`) and the gRPC `SetupService` (`x-setup-token`). **Required outside development**; never log it |
| `SECRET_DEFAULT_SCOPE_AUTOCREATE` | `true` | create the default tenant/project/environment on boot |
| `SECRET_DEFAULT_TENANT` | `default` | the scope the flat-key RPCs address |
| `SECRET_DEFAULT_PROJECT` | `default` | " |
| `SECRET_DEFAULT_ENVIRONMENT` | `default` | " |

A malformed numeric or boolean value is a **boot error**, not a silent fallback to the
default — a typo in a retention setting is a configuration change nobody made.
