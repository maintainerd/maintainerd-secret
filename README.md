# maintainerd-secret

A **standalone, encrypted secret store** — its own product. It runs on its own,
or attaches to maintainerd: Core calls `Setup` to register as controller (the
one-time setup pattern), after which system-Auth (IAM) governs access.

It is **built entirely on the kit** (`github.com/maintainerd/sdk/kit`) — shared
config, logging, the setup pattern, and the HTTP+gRPC server — so it repeats no
scaffolding.

## Owns

`maintainerd.secret.v1.SecretService` (gRPC on `:9092`): `Ping · Setup · Put ·
Get · List · Delete`. Generated stubs are in `gen/` (consumers import them; the
SDK's `sdk/secret` client wraps them).

## Encryption

Values are encrypted at rest with **AES-256-GCM** under a **root key** provided
at boot via `SECRET_ROOT_KEY` (env/KMS) — a store can't unlock itself, so the key
always comes from outside. v1 is in-memory; a durable backend plugs in behind the
`store` API.

## Run

```bash
SECRET_ROOT_KEY=$(head -c32 /dev/urandom | base64 | head -c32) make run
grpcurl -plaintext localhost:9092 maintainerd.secret.v1.SecretService/Ping
curl localhost:8092/healthz
```

## Config (env)

| Var | Default | Purpose |
|-----|---------|---------|
| `APP_ENV` | `development` | environment |
| `LOG_LEVEL` | `info` | log level |
| `SECRET_ROOT_KEY` | (ephemeral dev key) | 32-byte AES-256 root key |
| `SETUP_BOOTSTRAP_TOKEN` | (open) | token gating the one-time Setup |
| `GRPC_PORT` | `9092` | SecretService gRPC |
| `HTTP_PORT` | `8092` | HTTP liveness |
