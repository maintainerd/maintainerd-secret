# maintainerd-secret

**Open-source, self-hostable secret manager — envelope-encrypted, versioned, append-only.**

maintainerd's **own** vault, not a facade over anyone else's. Vault / AWS Secrets Manager / Azure Key Vault / GCP Secret Manager are *alternative providers you may choose instead of this service*; this service never proxies to them. Bring a **PostgreSQL** and a 32-byte root key, and you have a secret store with per-version envelope encryption, an audit trail that records reads, soft delete with a recovery window, and scheduled rotation.

Runs **standalone** — adopt just this plus maintainerd-auth — or **ecosystem-attached**, where Core registers as controller and system-Auth governs access.

- 📦 **Source & full docs:** https://github.com/maintainerd/maintainerd-secret
- 🔑 **Every environment variable:** https://github.com/maintainerd/maintainerd-secret#config-env
- 🐛 **Issues / questions:** https://github.com/maintainerd/maintainerd-secret/issues
- 📜 **License:** Apache-2.0

---

## Supported tags

| Tag | Meaning |
|-----|---------|
| `latest` | Current build — used by the quick start |
| `0.1.0` | The pre-release version (moving during testing; pin `latest` for the newest) |

**Architectures:** `linux/amd64`, `linux/arm64`. Each image carries SLSA provenance + an SBOM attestation, and each GitHub release carries a cosign-signed SPDX SBOM.

---

## What's inside

| Port | Surface | Expose publicly? |
|------|---------|------------------|
| `8092` | REST — `/api/v1` (guarded) + `/healthz` (unguarded) | ❌ behind a TLS-terminating edge only |
| `9092` | gRPC — `maintainerd.secret.v1.SecretService` / `SetupService` | ❌ internal |

The image also ships the built **console SPA** at `/srv/console` (declared as `CONSOLE_DIR`). Serve it from any static host pointed at those files.

You provide PostgreSQL; it is **not** in this image.

---

## Quick start

```bash
docker run -d --name m9d-secret \
  -p 8092:8092 -p 9092:9092 \
  -e APP_ENV=development \
  -e DB_HOST=... -e DB_PORT=5432 \
  -e DB_USER=postgres -e DB_PASSWORD=postgres -e DB_NAME=maintainerd_secret \
  -e SECRET_ROOT_KEY="$(openssl rand -hex 32)" \
  maintainerd/secret:latest

curl localhost:8092/healthz
curl localhost:8092/api/v1/setup/status
```

Schema migrations are embedded and applied in-process on boot.

> ⚠️ **Keep that root key.** Outside `APP_ENV=development` a missing or malformed `SECRET_ROOT_KEY` is a **boot error**, never a silently generated one — a generated key would make every secret written before the next restart permanently undecryptable, and the failure would stay invisible until far too late. Back the key with a real KMS or a mounted `0600` file in production.

---

## Environment variables

### Required in production

| Variable | Description |
|----------|-------------|
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | PostgreSQL connection. Never logged. |
| `SECRET_ROOT_KEY` | The 32-byte AES-256 root key (KEK) as hex or base64. Required outside development. |
| `SETUP_BOOTSTRAP_TOKEN` | Gates the one-time `Setup`. Required outside development. |
| `AUTH_JWKS_URL` / `AUTH_ISSUER` / `AUTH_AUDIENCE` | maintainerd-auth token verification. **All three together, or none** — a partial set is a boot error. With none set, the API is disabled outside development. |

### Common options

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Any other value fails closed: no ephemeral key, no open setup window, no gRPC reflection. |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error`. |
| `HTTP_PORT` | `8092` | REST API. |
| `GRPC_PORT` | `9092` | gRPC API. |
| `DB_SSLMODE` | `disable` | `disable` is refused outside development. |
| `SECRET_ROOT_KEY_PROVIDER` | `env` | `env` / `file` (built); `aws_kms` / `gcp_kms` / `azure_kv` (registered, not built). |
| `SECRET_ROOT_KEY_FILE` | — | Sealed key file for the `file` provider; must be `0600`. |
| `SECRET_KEEP_VERSIONS` | `10` | Versions retained per secret (min 1). |
| `SECRET_RECOVERY_WINDOW` | `720h` | How long a deleted secret stays restorable; `0` refused outside development. |
| `SECRET_ROTATION_ENABLED` | `true` | Background rotator. Turning it off preserves every policy. |
| `SECRET_WEBHOOKS_ENABLED` | `true` | Change/rotation notifications. A delivery never carries a value. |

> 👉 **The complete list — every variable, default, and production note — is in the [repo README](https://github.com/maintainerd/maintainerd-secret#config-env).**

---

## Production notes

- Terminate TLS in front of the container. `/healthz` is the only unguarded route; everything else requires a verified bearer token.
- Set `DB_SSLMODE=require` and configure all three `AUTH_*` variables — without them the API answers 503 outside development, by design.
- Source the root key from a KMS or a mounted `0600` file rather than plaintext env.
- Runs as a non-root user (uid 65532). Health endpoint: `GET /healthz` on `8092`.
- A malformed numeric or boolean value is a **boot error**, not a silent fallback — a typo in a retention setting is a configuration change nobody made.

---

<sub>Built by <a href="https://github.com/xreyc">Reyco Seguma (@xreyc)</a> and the Maintainerd community · Apache-2.0</sub>
