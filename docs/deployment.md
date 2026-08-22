# Deployment shape — resource limits and workload hardening

The platform's security baseline requires a service to **declare cpu/memory limits in
its own template** (`plan/16-security-baseline.md`). This document is that
declaration for maintainerd-secret, in the form an operator or maintainerd-core can
apply.

## Why this is a document and not a file core reads

There is no template file to edit. Worth stating plainly, because the obvious places
to look both turn out to be dead ends:

- **`maintainerd/internal/steward/builtin.go` declares no deployment shape.** It is
  the IAM catalog — `ServiceSpec`, `ResourceAPISpec`, `ServiceClientSpec`,
  `ServicePolicySpec` — and none of those types has an image, a resource, or a
  template field. The `secret` entry there is four identity objects and nothing about
  how the container runs.
- **Deployment templates are database rows, not repository files.** They live in
  core's `deployment_templates` table (`name`, `version`, `capability`, `image`,
  `parameters` JSONB, `spec` JSONB), and no template for `secret` is seeded anywhere
  today. The YAML import/export the catalog document describes is not implemented.

So the authoritative schema is the Go type the rendered `spec` must unmarshal into —
`kitruntime.WorkloadSpec` in `maintainerd-kit/runtime/spec.go` — and the block below
is written against that. Note also that `WorkloadSpec.Validate()` does **not** check
`Resources`: a template that omits limits passes validation silently, which is why
the baseline requirement has to be met by declaring them rather than by relying on
the platform to demand them.

---

## The spec

`resources` and `security` are the parts this document exists to fix. The rest is
context so the block is applyable rather than a fragment. Field names are the JSON
names `kitruntime.WorkloadSpec` expects — **snake_case, absolute units**, not
Kubernetes-style `"500m"` / `"512Mi"` strings.

```json
{
  "name": "m9d-secret",
  "image": "maintainerd/secret:{{ .version }}",
  "pull_policy": "if-not-present",

  "ports": [
    { "container_port": 8092, "host_port": "{{ .http_port }}" },
    { "container_port": 9092, "host_port": "{{ .grpc_port }}" }
  ],

  "env": {
    "APP_ENV": "production",
    "MAINTAINERD_MODE": "core",
    "HTTP_PORT": "8092",
    "GRPC_PORT": "9092",
    "DB_HOST": "{{ .db_host }}",
    "DB_PORT": "{{ .db_port }}",
    "DB_NAME": "{{ .db_name }}",
    "DB_USER": "{{ .db_user }}",
    "DB_PASSWORD": "{{ secretRef .db_password }}",
    "DB_SSLMODE": "require",
    "SECRET_ROOT_KEY_PROVIDER": "{{ .root_key_provider }}",
    "SETUP_BOOTSTRAP_TOKEN": "{{ secretRef .setup_bootstrap_token }}",
    "SECRET_GRPC_CERT_FILE": "/etc/maintainerd/tls/server.crt",
    "SECRET_GRPC_KEY_FILE": "/etc/maintainerd/tls/server.key",
    "SECRET_GRPC_CA_FILE": "/etc/maintainerd/tls/client-ca.crt"
  },

  "resources": {
    "cpu_shares": 1024,
    "cpu_quota": 100000,
    "memory_limit_bytes": 536870912,
    "memory_reservation_bytes": 134217728,
    "pids_limit": 256
  },

  "security": {
    "read_only_rootfs": true,
    "no_new_privileges": true,
    "cap_drop": ["ALL"]
  },

  "mounts": [
    { "type": "tmpfs", "target": "/tmp" },
    { "type": "bind", "source": "{{ .tls_dir }}", "target": "/etc/maintainerd/tls", "read_only": true }
  ],

  "health": {
    "test": ["CMD", "wget", "-qO-", "http://127.0.0.1:8092/readyz"],
    "interval": "10s",
    "timeout": "3s",
    "retries": 5,
    "start_period": "20s"
  },

  "restart_policy": { "name": "unless-stopped" },
  "stop_signal": "SIGTERM"
}
```

---

## The limits, and why each number

The service is a Go binary whose expensive work is done by PostgreSQL. Envelope
encryption is AES-256-GCM, which is hardware-accelerated and negligible next to the
query that fetched the row. So the profile is: **low steady CPU, low steady memory,
with a few bounded transient peaks** — and every one of those peaks is already
bounded by a configuration value, which is what makes it possible to size this
honestly rather than by guessing.

| Field | Value | Reasoning |
|---|---|---|
| `cpu_quota` | `100000` = **1.0 CPU** | Docker's quota is microseconds per 100 ms period, so 100000 is one full core. The service is I/O-bound on PostgreSQL; a core is generous for the API and leaves headroom for the one genuinely CPU-shaped job, a root-key rewrap, which does an unwrap+wrap per version row. Sized so a rewrap of a large store cannot starve the reveal path. |
| `cpu_shares` | `1024` | Docker's default weight, kept rather than lowered. Shares only matter under contention, and a **secret store is the wrong thing to deprioritise**: when the host is saturated, every other service is blocked waiting for a credential from this one. Equal weight, not less. |
| `memory_limit_bytes` | `536870912` = **512 MiB** | A hard ceiling roughly 10x steady state. The transients it must absorb, all of them already bounded: a batch get at `SECRET_MAX_BATCH_ITEMS` x `SECRET_MAX_VALUE_BYTES` (100 x 64 KiB = 6.4 MiB of plaintext, plus ciphertext and JSON encoding); a rewrap batch of `SECRET_REWRAP_BATCH_SIZE` = 500 wrap records (tens of KiB — a rewrap never reads a payload); the rate limiter's bucket map at `DefaultMaxKeys` = 50k entries (a few MiB); `DB_MAX_OPEN_CONNS` = 25 pooled connections; and webhook fan-out at `SECRET_WEBHOOK_CONCURRENCY` = 4. Summed with Go's heap slack and GC headroom, 512 MiB is comfortable and still small enough that a leak trips the limit rather than the host's OOM killer. |
| `memory_reservation_bytes` | `134217728` = **128 MiB** | The soft floor the scheduler honours. Set well above steady-state RSS so the service is not the first thing reclaimed when the host is under pressure — reclaiming the vault degrades every service that depends on it. |
| `pids_limit` | `256` | A Go process runs a handful of OS threads (GOMAXPROCS plus runtime helpers), and this service spawns no subprocesses at all. 256 is far above any legitimate need and turns a fork bomb — from a dependency, or from code execution in the container — into a bounded failure instead of a host-wide one. |

### Tune these up if

- **You raise `SECRET_MAX_VALUE_BYTES` or `SECRET_MAX_BATCH_ITEMS`.** They multiply
  directly into peak memory; a batch of 100 x 1 MiB values is 100 MiB of plaintext in
  flight, and the 512 MiB ceiling stops being comfortable.
- **You raise `DB_MAX_OPEN_CONNS`** well past 25.
- **You raise `SECRET_WEBHOOK_CONCURRENCY`** substantially — each in-flight delivery
  holds a payload and an HTTP client.
- **You run a very large store and want faster rewraps.** Raise `cpu_quota` for the
  duration of a rotation rather than permanently.

### Do not tune these down

Especially not `pids_limit` or `memory_reservation_bytes`. The failure modes are a
service that cannot start a goroutine's thread under load, and a vault that gets
reclaimed first when the host is squeezed — both of which present as intermittent
credential-fetch failures across every other service, which is one of the harder
things to diagnose.

---

## The hardening block

Not required by the baseline item, but this workload happens to satisfy the strict
settings, and a template is the place to say so while it is true.

- **`read_only_rootfs: true`** — the service writes nothing to disk. Migrations are
  embedded in the binary, logs go to stdout, and secrets go to PostgreSQL. The only
  filesystem write path is `/tmp`, covered by the tmpfs mount above.
- **`no_new_privileges: true`** — nothing in the container needs to escalate; there
  is no setuid binary and no subprocess.
- **`cap_drop: ["ALL"]`** — it binds ports 8092 and 9092, both above 1024, so it does
  not even need `CAP_NET_BIND_SERVICE`.
- **The TLS bind mount is `read_only`.** It carries the gRPC server key; the service
  reads it once at boot and never writes it.
- **`stop_signal: SIGTERM`** matches what the process handles: it drains in-flight
  requests, the rotator's current pass, and the leader lock within
  `SHUTDOWN_TIMEOUT` (default 20s). Keep the runtime's stop grace period **longer**
  than `SHUTDOWN_TIMEOUT`, or the drain is cut short by SIGKILL.

There is deliberately **no `privileged` field** in this contract —
`kitruntime.Security` does not have one, and `Validate()` rejects a `security_opt`
containing the word.

## Root-key material is not in this spec

`SECRET_ROOT_KEY` and `SECRET_ROOT_KEY_FILE` are absent on purpose. A rendered spec
is **persisted in `deployment_templates` and shipped over the wire**, so a root key
placed in `env` would be written to core's database in the clear — which would put
the key that decrypts the vault next to a copy of the vault. Supply it through the
runtime's own secret mechanism (`secretRef`, a mounted file, or a KMS provider that
never hands the material over at all), and see
[backup-restore.md](backup-restore.md) §1.2 for what has to be captured for each
provider.

## Multi-replica notes

Running more than one replica is supported and safe. Two things make it so, both on
by default:

- **`SECRET_LEADER_ELECTION_ENABLED`** (default `true`) — the background workers (the
  rotator, the webhook re-drive loop, the rate-limit pruner) run on exactly one
  replica, chosen by a PostgreSQL advisory lock. Without it, every replica rotates the
  same secret.
- **`SECRET_RATE_LIMIT_SHARED`** (default `true`) — the rate-limit budgets are shared
  across replicas rather than multiplied by the replica count.

The limits above are **per replica** and do not change with the replica count. The
one thing that does: the elected leader holds **one extra pooled connection** for the
lifetime of its leadership (that is how a session-scoped advisory lock works), so
`DB_MAX_OPEN_CONNS` needs to be at least 2 — which it is, at a default of 25.
