<div align="left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/maintainerd-icon-light.svg">
    <img src=".github/assets/maintainerd-icon-dark.svg" alt="" height="70" align="left">
  </picture>
  <h1>&nbsp;Maintainerd Secret</h1>
</div>

<br clear="left">

[![Release](https://img.shields.io/github/v/release/maintainerd/maintainerd-secret?logo=github&label=release&color=blue)](https://github.com/maintainerd/maintainerd-secret/releases/latest)
[![CI](https://github.com/maintainerd/maintainerd-secret/actions/workflows/ci.yml/badge.svg)](https://github.com/maintainerd/maintainerd-secret/actions/workflows/ci.yml)
[![Security](https://github.com/maintainerd/maintainerd-secret/actions/workflows/security.yml/badge.svg)](https://github.com/maintainerd/maintainerd-secret/actions/workflows/security.yml)
[![Licenses](https://github.com/maintainerd/maintainerd-secret/actions/workflows/licenses.yml/badge.svg)](https://github.com/maintainerd/maintainerd-secret/actions/workflows/licenses.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/maintainerd/maintainerd-secret/badge)](https://scorecard.dev/viewer/?uri=github.com/maintainerd/maintainerd-secret)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

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

| Provider | Where the KEK lives | Settings it needs |
|---|---|---|
| `env` | this process's memory, from `SECRET_ROOT_KEY` (32 bytes, hex or base64, validated) | `SECRET_ROOT_KEY` |
| `file` | a sealed key file; **refuses** a group/world-readable file | `SECRET_ROOT_KEY_FILE` (mode `0600`) |
| `aws_kms` | AWS KMS — the key material never leaves the service | `SECRET_KMS_AWS_KEY_ID`, `SECRET_KMS_AWS_REGION` |
| `gcp_kms` | Google Cloud KMS | `SECRET_KMS_GCP_KEY_NAME` |
| `azure_kv` | Azure Key Vault (RSA key, `RSA-OAEP-256`) | `SECRET_KMS_AZURE_VAULT_URL`, `SECRET_KMS_AZURE_KEY_NAME` |

**Outside `APP_ENV=development` a missing or malformed root key is a boot error** —
never a silently generated one. A generated key makes every secret written before the
next restart permanently undecryptable, and the failure is invisible until it is far
too late.

The same rule applies to the cloud providers, and it is why they are checked **twice
before the service serves a request**:

1. **Config validation.** Selecting a provider without its settings is a boot error
   naming every missing variable at once. A GCP key name is checked for shape (and a
   `/cryptoKeyVersions/...` suffix is refused — `Encrypt` accepts one, `Decrypt` does
   not, so a pinned version would wrap happily and fail every unwrap). An Azure vault
   URL must be `https`.
2. **A boot self-test.** Each cloud provider wraps and unwraps a throwaway probe
   during construction, so it exercises **both halves of the grant**. An IAM policy
   with encrypt but not decrypt is the failure this catches: without it the service
   starts, accepts writes, and discovers on the first read that it cannot decrypt
   anything it wrote. Cost: two KMS calls per process start.

#### How a cloud root key is bound

Each provider binds the wrap to **this service and this `kek_id`**, so a wrapped DEK
cannot be presented as though a different key or a different service had produced it —
the same property the AES providers get from GCM's AAD.

| Provider | Binding | Nonce |
|---|---|---|
| `aws_kms` | `EncryptionContext` (`maintainerd_service`, `kek_id`) — KMS authenticates it, and it also shows up in CloudTrail. `Decrypt` additionally **pins `KeyId`**, so a blob naming some other key is refused instead of decrypted | none — KMS returns one self-describing blob |
| `gcp_kms` | `AdditionalAuthenticatedData`, plus CRC32C checksums in both directions so a DEK corrupted in transit is refused rather than wrapped | none |
| `azure_kv` | `RSA-OAEP-256` has **no AAD channel**, so the binding is framed into the wrapped plaintext and verified on unwrap. (Key Vault's `AdditionalAuthenticatedData` field applies only to the authenticated symmetric algorithms; setting it under RSA-OAEP would be silently ignored — which looks like a binding and is not one) | none |

Every cloud call has a per-call deadline (`SECRET_KMS_TIMEOUT`, default `10s`) and
retries **transient failures only** — a throttle or a 5xx, up to three attempts with
jittered backoff. `AccessDenied`, `NotFound` and a failed decryption are not retried:
they read the same on the third attempt, and retrying turns one clear error into three
slow ones. No error from any provider carries a DEK or a wrapped blob, in any encoding.

#### Least-privilege IAM

Grant exactly these on the root key — nothing else is called.

**AWS KMS** — a symmetric `ENCRYPT_DECRYPT` key. On the key policy (or the service's
role), condition the grant on the encryption context so the key cannot be used for
anything else:

```json
{
  "Effect": "Allow",
  "Action": ["kms:Encrypt", "kms:Decrypt"],
  "Resource": "arn:aws:kms:us-east-2:111122223333:key/<key-id>",
  "Condition": {
    "StringEquals": { "kms:EncryptionContext:maintainerd_service": "maintainerd-secret" }
  }
}
```

**GCP KMS** — on the CryptoKey, not the project. The two permissions are
`cloudkms.cryptoKeyVersions.useToEncrypt` and
`cloudkms.cryptoKeyVersions.useToDecrypt`, both carried by the predefined role:

```bash
gcloud kms keys add-iam-policy-binding root \
  --location=us-east1 --keyring=secret \
  --member="serviceAccount:maintainerd-secret@<project>.iam.gserviceaccount.com" \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter
```

**Azure Key Vault** — the data-plane operations are `wrapKey` and `unwrapKey` (not
`encrypt`/`decrypt`, which would let this service encrypt arbitrary data):

```bash
# RBAC vaults: the built-in role that carries wrapKey/unwrapKey
az role assignment create --assignee <principal-id> \
  --role "Key Vault Crypto User" \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>"

# access-policy vaults: exactly the two operations
az keyvault set-policy --name <vault> --object-id <principal-id> --key-permissions get wrapKey unwrapKey
```

#### Operator smoke test

The unit suite proves the adapters against fakes; it cannot prove that *your* key
exists and *your* principal can reach it. Run one of these before deploying — a
failure here is the same failure the boot self-test would report, minus the outage.

```bash
# AWS — a real encrypt/decrypt round trip through the configured key
CT=$(aws kms encrypt --region "$SECRET_KMS_AWS_REGION" --key-id "$SECRET_KMS_AWS_KEY_ID" \
       --plaintext "$(openssl rand -base64 32)" --query CiphertextBlob --output text)
aws kms decrypt --region "$SECRET_KMS_AWS_REGION" --key-id "$SECRET_KMS_AWS_KEY_ID" \
  --ciphertext-blob "fileb://<(printf %s "$CT" | base64 -d)" --query Plaintext --output text >/dev/null && echo "aws_kms OK"

# GCP — same, against the CryptoKey named by SECRET_KMS_GCP_KEY_NAME
openssl rand 32 > /tmp/probe
gcloud kms encrypt --key "$SECRET_KMS_GCP_KEY_NAME" \
  --plaintext-file=/tmp/probe --ciphertext-file=/tmp/probe.enc
gcloud kms decrypt --key "$SECRET_KMS_GCP_KEY_NAME" \
  --ciphertext-file=/tmp/probe.enc --plaintext-file=/tmp/probe.out
cmp /tmp/probe /tmp/probe.out && echo "gcp_kms OK"; shred -u /tmp/probe /tmp/probe.enc /tmp/probe.out

# Azure — reachability and authentication. The az CLI has no wrap/unwrap verb, so the
# wrapKey/unwrapKey grant itself is what the boot self-test confirms.
az keyvault key show --vault-base-url "$SECRET_KMS_AZURE_VAULT_URL" \
  --name "$SECRET_KMS_AZURE_KEY_NAME" --query "key.kty" -o tsv && echo "azure_kv reachable"
```

#### Rotating between providers

Rotation re-wraps DEKs and **never rewrites ciphertext**, so moving the root of trust
between any two providers — `env` → `aws_kms`, `aws_kms` → `gcp_kms`, anything → 
anything — is an update of a few dozen bytes per version rather than a re-encryption
of the store.

1. Provision the new key and grant the two permissions above.
2. Point `SECRET_ROOT_KEY_PROVIDER` (and the new provider's settings) at it, **keeping
   the old provider's settings in place** — the old key must stay loadable until the
   rewrap has drained it. Settings for an unselected provider are read and not
   validated, precisely so both can coexist through a migration.
3. Restart. The new key becomes the active write key and is registered in `root_keys`;
   existing versions keep their recorded `kek_id` and stay readable through the
   keyring.
4. Run the rewrap. It is batched (`SECRET_REWRAP_BATCH_SIZE`), resumable — progress
   lives in the data, so a crashed pass is resumed by running it again — and
   idempotent. The old key is retired only once a `COUNT` proves no version still
   references it; a key retired early would leave those rows permanently unreadable.
5. Remove the old provider's settings once `root_keys` shows it retired.

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
which is what makes the guard's permission allowlist meaningful: with everything
nested under `/projects`, one entry would cover the whole API. An unmapped surface is
denied even to a valid token.

Reveal and batch-get are **POSTs despite being reads**. A secret's address in a URL
ends up in access logs, proxy logs, browser history and referer headers; a body does
not. The permission required is still the *reveal* one — the HTTP verb is a transport
detail and the privilege is not.

### Authorization

**Permission checking is the SDK's job.** Every route and every RPC is guarded
through `github.com/maintainerd/sdk/authz` — the shared enforcement point every
maintainerd service and third-party resource server uses. This repo contributes only
its *vocabulary*: the `secret:` permission constants, the route table (with each
surface's actor class), the gRPC method table and the exemption set, expressed as one
`authz.Map` in
[`internal/platform/permissions`](internal/platform/permissions/permissions.go).
There is no hand-rolled authorization code here any more.

Two layers, answering different questions. The **surface guard** verifies the bearer
token (Auth's JWKS + issuer + audience), checks that this **class** of caller is
allowed on the surface, and checks the permission the surface actually performs; the
**operation check** decides whether *this* principal may perform *this* action on
*this* MRN — and enforces any *second* permission the operation needs. Both are
required — layer 1 alone is a vault where anyone who may read one secret may read all
of them.

**The route guard names the real permission, not a baseline.** It runs *first*, so a
deliberately weak entry there is the check an attacker meets at the door, and a new
handler that forgets its layer-2 check would inherit that weakness silently. Every
route on `/secrets` and `/bulk` is therefore declared **exactly** (method + path); the
segment pair is kept only for the nouns that genuinely are *"browse these, manage
these"*. Those two segments have **no** pair at all, which is stronger than a weak one:
a new route mounted beside them matches nothing and is denied to every caller.

The route/method table **is the allowlist**: an unmapped surface is denied even to a
valid token, so mounting a route or registering an RPC without deciding its permission
fails closed instead of shipping open. A test walks the live chi router and the live
gRPC service descriptors, checks each surface against a written specification of what
it should demand, and fails if either grows a surface the table does not account for —
see [The gap audit](#the-gap-audit).

#### Two trust contexts: service-to-service and console

Two classes of caller reach this vault, and the distinction is **not** expressible as
a permission:

- a **user principal** — signed in to the console through an interactive OAuth2
  authorization-code + PKCE flow, with a browser session behind it;
- a **service principal** — a machine identity carrying Auth's `svc` claim, calling
  m2m. Workloads fetching their own secrets are the whole point of this service.

A permission answers *"may this principal do X"*. Only the actor kind answers *"should
this class of caller be doing X at all"* — and that is the question that catches a
**stolen m2m credential**, whose grants are entirely real so no permission check will
ever refuse it. A workload creating a project, rewiring a webhook, destroying a secret
or reading the audit trail is by itself the signal.

| Actor | Surfaces |
|---|---|
| **user only** | project · environment · folder · scope-import **writes**; webhook management; rotation-policy management; `restore` and `destroy`; the audit trail |
| **either** | reveal, batch get, describe, list, version history; the ordinary write / rotate / soft-delete of a secret; every hierarchy **read** |

Service principals are allowed to **write and rotate** — deliberately. A rotator
replacing the credential it manages and a reconciler converging an environment it owns
are first-class m2m cases, and the blast radius is bounded by the MRN grant rather than
by the caller's class. Restricting writes to humans would push rotation back into a
person's hands, which is the outcome a secret store exists to remove. `restore` and
`destroy` are the exceptions because both authorize at **tenant scope** (the project
and environment are unknown until the row is read), so they need a grant far wider than
any single workload's.

A refusal carries the distinct code **`actor_kind_not_permitted`** rather than
`insufficient_permission`, because widening a grant is not the fix for a workload on
the console surface. The status stays `403` / `PermissionDenied` — the reason differs,
the answer does not — and the check runs *before* the permission check, so a
wrong-class caller is never handed the name of the grant it would need.

The class is derived from the **verified** claims (`authz.ActorKindFromClaims`), never
from a header or any other caller-supplied field, and it is recorded on every audit row
— which is what lets an incident review separate *"a human read the production database
password"* from *"the billing workload read its own credential"*.

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

#### REST routes → permission + actor

Every route on `/secrets` and `/bulk` is declared **exactly** (method + path), because
one segment pair could only ever be as strong as the weakest route on the segment.

| Route | Permission | Actor | Also enforced per-MRN in `internal/api` |
|---|---|---|---|
| `GET /secrets` | `secret:ListSecrets` | either | — |
| `GET /secrets/deleted` | `secret:ListSecrets` | either | — |
| `GET /secrets/describe` | `secret:ReadMetadata` | either | — |
| `GET /secrets/versions` | `secret:ReadMetadata` | either | — |
| `POST /secrets/reveal` † | `secret:GetSecret` | either | re-checked at **every reference hop** |
| `POST /secrets` | `secret:PutSecret` | either | — |
| `PATCH /secrets` | `secret:PutSecret` | either | — |
| `POST /secrets/rollback` | `secret:PutSecret` | either | **`secret:GetSecret`** ‖ |
| `POST /secrets/rotate` | `secret:RotateSecret` | either | — |
| `POST /secrets/rotation-policy` | `secret:ManageRotation` | **user** | — |
| `POST /secrets/delete` | `secret:DeleteSecret` | either | — |
| `POST /secrets/restore` | `secret:DeleteSecret` | **user** | authorized at **tenant** scope |
| `POST /secrets/destroy` | `secret:DeleteSecret` | **user** | authorized at **tenant** scope; irreversible |
| `POST /bulk/get` † | `secret:GetSecret` | either | **every item**, on its own MRN |
| `POST /bulk/put` | `secret:PutSecret` | either | **every item**, on its own MRN |

The remaining segments are uniform, so they keep the read/write pair: `GET`/`HEAD`
requires the read permission, every other verb the write one.

| Segment | Read (`GET`/`HEAD`) | Write (everything else) | Actor (read / write) | Also enforced per-MRN |
|---|---|---|---|---|
| `/projects` | `secret:ReadMetadata` | `secret:ManageProject` | either / **user** | — |
| `/environments` | `secret:ReadMetadata` | `secret:ManageEnvironment` | either / **user** | — |
| `/folders` | `secret:ReadMetadata` | `secret:ManageFolder` | either / **user** | `DELETE`: **`secret:DeleteSecret`** ‖ · `POST /move`: `ManageFolder` on **both** MRNs |
| `/imports` | `secret:ReadMetadata` | `secret:ManageFolder` | either / **user** | `POST`: **`secret:GetSecret`** on the *source* scope ‖ |
| `/webhooks` | `secret:ReadMetadata` | `secret:ManageRotation` | either / **user** | — |
| `/audit` | `secret:ReadAudit` | `secret:Admin` | **user** / **user** | — |
| `/setup` | *exempt* ‡ | *exempt* ‡ | — | — |
| `/healthz`, `/readyz` | *exempt* ‡ | — | — | — |

† A `POST` carrying a **read** — a secret's address belongs in a body, not in an access
log. The verb is a transport detail; the permission is the reveal one.

‖ **A second permission, on top of the one at the door.** A rollback republishes a value
the caller did not supply, so a principal that may write but not read could otherwise
use it as a read primitive. Deleting a folder deletes the secrets under it, so folder
management alone must not be a way to delete values. A scope import makes another
scope's values readable through this one, so creating it requires the ability to read
them. In each case the route guard demands the **primary** permission and
`internal/api` enforces the rest against the concrete target MRN — which is the only
place a resource-dependent second check can be made.

‡ See [Exemptions](#exemptions).

#### gRPC methods → permission + actor

`maintainerd.secret.v1.SecretService`. The two transports are thin adapters over one
application service, so this table **must agree with the REST one surface by surface** —
otherwise a caller refused over REST would simply open a gRPC channel. A test asserts
the pairing.

| Method | Permission | Actor | Also enforced per-MRN |
|---|---|---|---|
| `Put` | `secret:PutSecret` | either | — |
| `Get` | `secret:GetSecret` *(the legacy flat Get is a reveal)* | either | — |
| `List` | `secret:ListSecrets` | either | — |
| `Delete` | `secret:DeleteSecret` | either | — |
| `CreateProject` · `UpdateProject` · `DeleteProject` | `secret:ManageProject` | **user** | — |
| `ListProjects` · `GetProject` | `secret:ReadMetadata` | either | — |
| `CreateEnvironment` · `UpdateEnvironment` · `DeleteEnvironment` | `secret:ManageEnvironment` | **user** | — |
| `ListEnvironments` · `GetEnvironment` | `secret:ReadMetadata` | either | — |
| `CreateFolder` · `MoveFolder` | `secret:ManageFolder` | **user** | `MoveFolder`: both MRNs |
| `DeleteFolder` | `secret:ManageFolder` | **user** | **`secret:DeleteSecret`** ‖ |
| `ListFolders` | `secret:ReadMetadata` | either | — |
| `CreateImport` | `secret:ManageFolder` | **user** | **`secret:GetSecret`** on the source ‖ |
| `UpdateImport` · `DeleteImport` | `secret:ManageFolder` | **user** | — |
| `ListImports` | `secret:ReadMetadata` | either | — |
| `GetSecret` | `secret:GetSecret` | either | re-checked at every reference hop |
| `DescribeSecret` · `ListSecretVersions` | `secret:ReadMetadata` | either | — |
| `ListSecrets` · `ListDeletedSecrets` | `secret:ListSecrets` | either | — |
| `PutSecret` · `UpdateSecretMetadata` | `secret:PutSecret` | either | — |
| `RollbackSecret` | `secret:PutSecret` | either | **`secret:GetSecret`** ‖ |
| `RotateSecret` | `secret:RotateSecret` | either | — |
| `SetRotationPolicy` | `secret:ManageRotation` | **user** | — |
| `DeleteSecret` | `secret:DeleteSecret` | either | — |
| `RestoreSecret` · `DestroySecret` | `secret:DeleteSecret` | **user** | tenant scope |
| `BatchGetSecrets` | `secret:GetSecret` | either | every item, on its own MRN |
| `BatchPutSecrets` | `secret:PutSecret` | either | every item, on its own MRN |
| `CreateWebhookEndpoint` · `UpdateWebhookEndpoint` · `DeleteWebhookEndpoint` | `secret:ManageRotation` | **user** | — |
| `ListWebhookEndpoints` · `ListWebhookDeliveries` | `secret:ReadMetadata` | either | — |
| `ListAuditEvents` | `secret:ReadAudit` | **user** | — |
| `Ping` · `Setup` | *exempt* ‡ | — | — |

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
tomorrow rather than only today — and it is now a **specification** rather than a
presence check. It:

1. builds the **real chi router** this service mounts and walks it with `chi.Walk`;
2. flattens the **generated `grpc.ServiceDesc` values** `grpc.Server` dispatches on —
   unary methods *and* streams;
3. requires every one to match its row in `restSpec` / `grpcSpec` **exactly** — the
   permission *and* the actor class — or be covered by an exemption that has a
   **written justification** in the test file;
4. fails any surface whose handler **mutates durable state** but resolves to a
   read-only permission (`ReadMetadata`, `ListSecrets`, `ReadAudit`);
5. asserts the REST and gRPC tables **agree** surface by surface, so a rule cannot hold
   on one transport and not the other;
6. checks the reverse directions — no mapped segment, exact route or method that
   nothing serves, and no spec row describing a surface that no longer exists;
7. checks itself for vacuity, by requiring surfaces that do *not* exist to read as
   gaps.

**Why the spec tables are not a mirror of the map.** Each row was derived by reading
the handler, following it to its `internal/api` method, and recording the permission
that method's `s.guard` call actually demands. A table that merely restated
`permissions.Map()` would pass forever and prove nothing; these disagree loudly if
either side moves. The `mutates` column is likewise a fact about the **handler**, not
the HTTP verb — a reveal is a `POST` and is not a mutation, a rollback is a `POST` and
is.

Requiring only a *non-empty* permission — what this test used to do — is a much weaker
property than it looks: a route mapped to the weakest permission in the vocabulary
passes it exactly as well as one mapped to the right permission.

The surface lists are derived from the live surface, never hand-kept, because a
hand-kept list drifts silently and a test that has stopped reading the surface is worse
than no test: it reports "no gaps" with confidence.

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
| `SECRET_KMS_TIMEOUT` | `10s` | bounds ONE cloud wrap or unwrap. The root key is on the read and write path of every secret, so an unbounded call would hold a request goroutine as long as the network allowed |
| `SECRET_KMS_AWS_KEY_ID` | — | **required for `aws_kms`.** Key ARN, key id, `alias/...` name, or alias ARN of a symmetric `ENCRYPT_DECRYPT` key |
| `SECRET_KMS_AWS_REGION` | — | **required for `aws_kms`** (falls back to `AWS_REGION`, then `AWS_DEFAULT_REGION`). Explicit because the region is part of the `kek_id`: an alias is region-scoped |
| `SECRET_KMS_GCP_KEY_NAME` | — | **required for `gcp_kms`.** `projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}`. A `/cryptoKeyVersions/...` suffix is refused at boot |
| `SECRET_KMS_AZURE_VAULT_URL` | — | **required for `azure_kv`.** `https://{vault}.vault.azure.net/`; must be `https` |
| `SECRET_KMS_AZURE_KEY_NAME` | — | **required for `azure_kv`.** The RSA key's name in that vault |
| `SECRET_KMS_AZURE_KEY_VERSION` | — | optional; empty means the vault's current version, which is the normal choice |

Only the **selected** provider's settings are required. Settings for the others are
read and left unvalidated on purpose, so an operator mid-migration can keep both sets
in place through the rewrap. Credentials are resolved by each cloud's own SDK chain —
AWS: environment, instance role, web identity (IRSA), shared profile; GCP: Application
Default Credentials; Azure: `DefaultAzureCredential` — this service reads none of them
itself.

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

### Transport security

Two listeners, two postures, and the asymmetry is deliberate.

**gRPC** is the service-to-service and **control-plane** surface: it carries
`SetupService`, through which maintainerd-core provisions this vault and records
itself as controller. A bearer token *asserts* that a peer is core; a verified client
certificate *proves* it. All three variables together, or none.

| Var | Default | Purpose |
|---|---|---|
| `SECRET_GRPC_CERT_FILE` | — | this service's gRPC server certificate |
| `SECRET_GRPC_KEY_FILE` | — | its private key |
| `SECRET_GRPC_CA_FILE` | — | the CA whose **client** certificates this listener accepts. Its presence is what makes the listener mutual: `tls.RequireAndVerifyClientCert`, so an unverified peer never reaches an interceptor |

When configured: **TLS 1.2 minimum**, and a cipher policy narrowed to suites that are
both forward-secret (ECDHE) and AEAD (GCM or ChaCha20-Poly1305). No CBC suites, so
none of the padding-oracle family; no static-RSA suites, so recorded traffic cannot be
decrypted later from a leaked server key. TLS 1.3 is negotiated in preference whenever
the peer supports it, and its suites are not configurable because all three are
already AEAD and forward-secret.

Fail-closed behaviour, by case:

| Situation | Result |
|---|---|
| **Partial** set (one or two of the three) | **Boot error, in every environment** — including development. This is the case that looks configured: a cert and key with no CA is server-only TLS that accepts *any* client while the operator believes peers are verified |
| None set, `MAINTAINERD_MODE=core`, outside development | **Boot error.** In core mode this listener is the control plane and is never served in the clear — no silent plaintext downgrade |
| None set, `standalone`, outside development | **Loud warning, every boot.** Service-to-service traffic between workloads you already run, commonly with a mesh terminating mTLS below this process. Refusing would break those deployments to protect them from a risk they have already handled |
| None set, `APP_ENV=development` | Plaintext. The laptop case the development degrade exists for |
| Bad material (unreadable file, CA with no PEM, mismatched key) | **Boot error** naming the file. There is no path from bad material to a plaintext listener |

**HTTP** is the REST API and the console's origin, and in every sanctioned deployment
it sits behind a terminating proxy (nginx in the dev stack, an ingress in production).
Direct TLS is therefore **optional** — offered for the operator who serves it
directly, not mandated for the majority who do not.

| Var | Default | Purpose |
|---|---|---|
| `SECRET_TLS_CERT_FILE` | — | serve the REST surface over TLS directly. Both or neither; one alone is a boot error |
| `SECRET_TLS_KEY_FILE` | — | " |

When set, the same TLS 1.2 floor and cipher policy apply. HSTS is unaffected either
way: it is emitted in production when the request arrived over TLS directly *or*
through a proxy that says so via `X-Forwarded-Proto`, so the terminating-proxy
deployment is already covered.

**gRPC reflection is registered only in development** and announces itself loudly when
it is. Reflection enumerates every RPC and message — convenient with `grpcurl` on a
laptop, a map of the vault's API handed to anyone who can open a socket in production.
There is no pprof, expvar, or other debug surface in the binary at all.

### Multi-replica (HA)

Every request surface is safe on N replicas. The **background work** is not, so it is
gated on a leader lock — a PostgreSQL **advisory lock**, chosen because it needs no
new dependency and, being session-scoped, **dies with the connection**: a crashed
leader frees the lock with no lease to expire and no reaper to run. See
[`internal/leader`](internal/leader/leader.go) for the full contrast with a lease
table.

| Var | Default | Purpose |
|---|---|---|
| `SECRET_LEADER_ELECTION_ENABLED` | `true` | run the background workers (rotator, webhook re-drive, rate-limit pruning) on exactly one replica |
| `SECRET_RATE_LIMIT_SHARED` | `true` | meter the rate-limit budgets through PostgreSQL so they span the replica set |

**Both default on, because the failures they prevent are invisible.** Two replicas
both rotating produce two versions and two webhook fan-outs for one secret — a
consumer that re-read after the first notification is holding a value that is already
superseded — and the service looks perfectly healthy doing it. A per-process rate
limit on three replicas is a reveal budget of 3x the configured number, and the reveal
budget is the exfiltration bound on a compromised token. An operator should have to
opt *out* of correctness, not in; turning either off warns at boot rather than
refusing, because both are legitimate for a single-replica deployment.

The shared rate limiter **reserves** slices of the window's budget rather than
counting per request, so it costs no database round trip on the hot path — and the
trade-off is stated honestly in
[`rate_limit.go`](internal/platform/middleware/rate_limit.go): a replica that reserves
a slice and goes idle strands the unspent remainder for the rest of the window, so the
fleet-wide ceiling holds exactly while the floor is slightly lower than a perfect
global counter's. If the database is unreachable it **degrades to per-replica
metering** — never to no limit, and never to refusing everything.

A malformed numeric or boolean value is a **boot error**, not a silent fallback to the
default — a typo in a retention setting is a configuration change nobody made.

## Operations

| Document | What it covers |
|---|---|
| [`docs/backup-restore.md`](docs/backup-restore.md) | The backup and restore runbook. **Start with its first paragraph:** the root key is not in the database, so a database backup alone is unrestorable. Covers what to capture per root-key provider, the `pg_dump`/`pg_restore` flags that matter, how the append-only triggers on `secret_versions` and `audit_log` interact with a restore, how to *prove* a restore worked, and why restoring across a root-key rotation is survivable |
| [`docs/deployment.md`](docs/deployment.md) | The declared cpu/memory limits and workload hardening for a core-attached install, with the reasoning behind each number and what to re-tune if you raise the request limits |
