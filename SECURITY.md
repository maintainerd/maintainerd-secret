# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✅ Active support   |
| < 1.0    | ❌ Development only |

## Reporting a Vulnerability

**Do not open a public issue.** Report security vulnerabilities privately to:

**Email:** security@maintainerd.dev

Include:
- A detailed description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential mitigations you've identified

We aim to acknowledge reports within 48 hours and provide a fix timeline within 5 business days. Critical vulnerabilities are typically patched within 72 hours.

## Threat Model

This service is a **vault**. The design assumption is that its database will eventually be read by someone who should not have it — a stolen backup, a misconfigured replica, a compromised host — and that this must not be enough to recover a single secret value.

### Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Operator / console → REST API (`:8092`) | Untrusted — bearer token verified against maintainerd-auth's JWKS, then a per-operation permission check on the MRN |
| Service mesh → gRPC API (`:9092`) | Untrusted — the same auth interceptor runs on every RPC; reflection is registered in development only |
| Anyone → `/healthz` (`:8092`) | Unauthenticated by design — mounted outside the `/api/v1` group and returns liveness only, never state |
| Application → PostgreSQL | Ciphertext only; `DB_SSLMODE=disable` is refused outside development |
| Application → root key provider | The KEK comes from **outside** the database (`env`, `file`, or a KMS) — a store cannot unlock itself |
| Service → webhook receiver (outbound) | A delivery describes a change; it **never** carries a secret value |

### Assets

| Asset | Sensitivity | Protection |
|-------|-------------|------------|
| Root key (KEK, AES-256) | Critical | Supplied from outside the DB; absent/malformed is a **boot error** outside development, never a generated key |
| Data encryption keys (DEKs) | Critical | One per version, wrapped by the KEK, zeroized after use, never logged or serialized |
| Secret payloads | Critical | AES-256-GCM, per-version DEK, `(tenant, secret, version)` bound as AAD; live only in `secret_versions` |
| Setup bootstrap token | High | Gates the one-time `Setup`; required outside development; never logged |
| Audit records | High | Append-only; record reads (`secret.read`) and reveals (`secret.reveal`) as distinct actions |
| Secret metadata (names, paths) | Medium | Behind `secret:ReadMetadata`, a **different grant** from `GetSecret` |

### Attack Surface

| Vector | Mitigation |
|--------|------------|
| Stolen database / backup | Envelope encryption; ciphertext alone is useless without the externally supplied root key |
| Ciphertext relocation (copy a row into another secret) | `(tenant UUID, secret UUID, version)` bound as AAD — authentication fails rather than decrypting into the wrong place |
| Cross-tenant read | `tenant_id` is in the `WHERE` clause of every secret query; sqlc will not compile a call that omits it |
| Over-broad token | Two layers: the surface guard checks the segment's baseline permission, then the operation check authorizes the principal against **this** MRN |
| Unmapped/new API surface | The guard's per-segment allowlist denies an unmapped segment even to a valid token |
| Missing auth configuration | Outside development the API does **not** degrade to open — REST answers 503 and gRPC serves health only |
| Partial auth configuration | A JWKS URL without an issuer and audience is a **boot error**: it would accept any token Auth ever signed, including tokens minted for another service |
| Secret address leaking into logs | Reveal and batch-get are POSTs despite being reads, so a key never lands in an access log, proxy log, browser history or referer header |
| Value leaking through an error or log line | A decrypted value is a `crypto.Plaintext` rendering as `[REDACTED]` through `String`, `%v`, `slog` and `json.Marshal`; no error carries a value, DEK or root key |
| History rewrite | `secret_versions` is append-only, enforced by a database trigger |
| Premature destruction | Soft delete schedules destruction; hard destroy inside the recovery window is refused by the SQL itself, against the database's own clock |
| Unreadable rows after a rotation | `RewrapAll` is batched, resumable and idempotent; the old key retires only once a `COUNT` proves nothing references it |
| Key file exposure | The `file` provider **refuses** a group/world-readable key file |
| API map disclosure | gRPC reflection is registered only when `APP_ENV=development` |
| Secret committed to the repo | Gitleaks over the full history in CI (`.gitleaks.toml`) |
| Vulnerable dependency | govulncheck (reachability-aware, includes the stdlib), Dependabot, and a Trivy image scan that blocks the release before anything is pushed |

## Security Features

| Feature | Implementation |
|---------|---------------|
| Encryption at rest | Envelope: AES-256-GCM per-version DEK, wrapped by an AES-256 root key |
| AAD binding | `(tenant UUID, secret UUID, version)` — immutable coordinates, so a folder move never destroys readability |
| Root of trust | Pluggable provider: `env`, `file` (built); `aws_kms`, `gcp_kms`, `azure_kv` (registered, not built) |
| Key rotation | Re-wraps DEKs, never rewrites ciphertext; batched, resumable, idempotent |
| Integrity / change detection | SHA-256 checksum of the plaintext; an unchanged write creates no new version |
| Memory hygiene | Plaintexts and DEKs zeroized after use; redacting `Plaintext` type |
| Versioning & retention | Append-only versions, configurable `KeepVersions`; pruning never deletes the current version |
| Soft delete | Recovery window with a database-clock-enforced `destroy_after` |
| Authorization | JWKS + issuer + audience verification, per-segment baseline permission, per-MRN operation check |
| Audit logging | Append-only; reads and reveals recorded as distinct actions |
| Setup lock | Durable one-shot lock in `setup_state`, not process memory — a restart does not reopen the window |
| Transport | TLS terminated at the edge; `DB_SSLMODE=disable` refused outside development |
| Container | Multi-stage build, pinned base-image digests, non-root user (uid 65532), no build secrets in layers |
| Supply chain | Multi-arch build with SLSA provenance + SBOM attestation; SBOM signed with cosign keyless on each release |

## Dependencies

We use Dependabot to monitor dependency updates. CI runs `govulncheck` on every push, PR and nightly, and blocks on any **called** vulnerability; `go-licenses` blocks forbidden/restricted licenses. The console's production dependency tree is audited with `npm audit --omit=dev --audit-level=high`.

## Acknowledgments

We appreciate the security research community. Hall of Fame contributors will be listed here with permission.
