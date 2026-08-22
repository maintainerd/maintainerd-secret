# =============================================================================
# maintainerd-secret — production image
#
# Ships the secret service (gRPC + REST) and the built console SPA in one image.
#
#   :9092  gRPC   maintainerd.secret.v1.SecretService / SetupService
#   :8092  REST   /api/v1 (guarded) + /healthz (unguarded)
#
# Postgres is NOT in this image — provide it via your platform. Local development
# does NOT use this image: maintainerd-dev runs the service and the console in
# hot-reload mode.
#
# -----------------------------------------------------------------------------
# BUILD CONTEXT REQUIREMENT — sibling modules
# -----------------------------------------------------------------------------
# go.mod replaces github.com/maintainerd/kit and github.com/maintainerd/sdk with
# workspace-local paths (../maintainerd-kit, ../maintainerd-sdk). A Docker build
# cannot reach outside its context, so those two modules must be present INSIDE
# the context at .deps/kit and .deps/sdk before you build. The Dockerfile then
# repoints the replaces at them (it never mutates the go.mod in your worktree).
#
#   make docker-prep && make docker-build      # local: copies the siblings in
#   (CI does the same with actions/checkout into .deps/kit and .deps/sdk)
#
# -----------------------------------------------------------------------------
# WIRING STILL REQUIRED — the console is shipped but not yet SERVED
# -----------------------------------------------------------------------------
# maintainerd-auth compiles its SPAs INTO the binary with go:embed behind an
# `embedassets` build tag. maintainerd-secret has no such embed point today: the
# only go:embed in this repo is migrations/embed.go, and internal/httpapi serves
# the JSON API only — there is no static file handler and no config key naming a
# console directory. Adding that is Go work and deliberately out of scope here.
#
# So this image BAKES the built SPA at /srv/console and declares CONSOLE_DIR as
# the contract, but nothing reads it yet. To finish the wiring, the Go side needs:
#
#   1. A config key — e.g. CONSOLE_DIR in internal/platform/config, empty by
#      default so the current behaviour is unchanged when it is not set.
#   2. A static handler in internal/httpapi/server.Router() mounted at "/",
#      OUTSIDE the /api/v1 guarded group and alongside /healthz, serving
#      CONSOLE_DIR with an index.html fallback for unknown paths (the console is
#      a client-side-routed SPA, so a deep link must not 404).
#   3. Optionally a dedicated console port if the SPA should not share :8092
#      with the API — in which case add its EXPOSE and HEALTHCHECK probe below.
#
# Until then the SPA can be served by any static host pointed at the files, or
# extracted from the image; nothing about this image needs to change once the
# handler lands. The SPA's own settings are read at RUNTIME from
# /srv/console/config.js (window.__ENV__), so one built image targets several
# deployments without a rebuild.
#
# NOTE: VERSION is used for the OCI label only. There is no AppVersion variable
# in internal/platform/config to -X into, unlike maintainerd-auth. Add one and
# this build picks it up with a single ldflags edit.
# =============================================================================

# --- Stage 1: build the console SPA ---
# SPA output is architecture-independent, so build on BUILDPLATFORM (never under
# QEMU emulation for arm64 — npm/vite under emulation is slow and OOM-prone).
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS console
WORKDIR /app
COPY web/console/package*.json ./
RUN npm ci
COPY web/console/ ./
# `npm run build` is `tsc -b && vite build`, so a type error fails the image build.
RUN npm run build

# --- Stage 2: build the Go binary ---
# Build on the native BUILDPLATFORM and cross-compile via GOOS/GOARCH so multi-arch
# builds never run this stage under QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS backend
ENV GOTOOLCHAIN=auto

RUN apk add --no-cache git ca-certificates
WORKDIR /app
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

COPY . .

# Fail fast with an actionable message rather than a wall of
# "replacement directory ../maintainerd-kit does not exist".
RUN if [ ! -d .deps/kit ] || [ ! -d .deps/sdk ]; then \
      echo "ERROR: .deps/kit and .deps/sdk must be present in the build context."; \
      echo "       Run 'make docker-prep' first (CI checks them out with actions/checkout)."; \
      exit 1; \
    fi

# Repoint the workspace replaces at the in-context copies. Done here, not in the
# worktree, so building an image never leaves a dirty go.mod behind.
RUN go mod edit -replace github.com/maintainerd/kit=./.deps/kit \
 && go mod edit -replace github.com/maintainerd/sdk=./.deps/sdk \
 && go mod download

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath -ldflags="-s -w" \
    -o /secretd ./cmd/secretd

# --- Stage 3: runtime ---
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG VERSION=dev
LABEL org.opencontainers.image.title="maintainerd-secret" \
      org.opencontainers.image.description="maintainerd's first-party secret manager — envelope-encrypted, versioned, append-only, with its own console" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="maintainerd" \
      org.opencontainers.image.source="https://github.com/maintainerd/maintainerd-secret" \
      org.opencontainers.image.documentation="https://github.com/maintainerd/maintainerd-secret/blob/main/README.md"

RUN apk add --no-cache ca-certificates curl tini \
    && addgroup -g 65532 m9d \
    && adduser -D -u 65532 -G m9d m9d

COPY --from=backend /secretd /usr/local/bin/secretd

# The console's static build. Owned by root and world-readable: the service only
# ever needs to READ these files, and a vault process should not be able to
# rewrite the UI it serves.
COPY --from=console --chown=root:root /app/dist /srv/console

# The contract for the static handler described in the header. Inert until the
# Go side reads it; harmless if it never does.
ENV CONSOLE_DIR=/srv/console

# 8092 is the REST API (and, once wired, the console). 9092 is gRPC. Neither
# should be exposed to the public internet without a TLS-terminating edge in
# front — this is a vault, and /healthz is the only unguarded route on 8092.
EXPOSE 8092 9092

# Generous start-period: the service loads the root key, connects to Postgres and
# runs schema migrations in-process before it starts answering.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=5 \
    CMD curl -fsS http://localhost:8092/healthz >/dev/null || exit 1

USER m9d

# tini is PID 1: reaps zombies and forwards SIGTERM to the service, which drains
# the gRPC and HTTP servers and stops the rotator before exiting.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/secretd"]
