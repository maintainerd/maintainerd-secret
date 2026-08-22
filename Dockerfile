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
# THE CONSOLE IS SERVED BY THE BINARY, from /srv/console
# -----------------------------------------------------------------------------
# The SPA is built in stage 1, baked at /srv/console, and served by the Go
# process itself on the REST port: no nginx, no second container, no static host
# in front. The contract is the CONSOLE_DIR variable declared below —
# internal/platform/config reads it (empty disables serving) and
# internal/httpapi mounts a traversal-safe static handler OUTSIDE the guarded
# /api/v1 group, with an index.html fallback so SPA deep links survive a hard
# refresh. Config REFUSES TO BOOT if CONSOLE_DIR is set but holds no readable
# index.html, so a broken bake is a log line rather than a site of 404s.
#
# WHY A DIRECTORY AND NOT go:embed. maintainerd-auth compiles its SPAs into its
# binary behind an `embedassets` build tag, which suits it: two SPAs, two
# dedicated ports, each needing its API same-origin for __Host- cookies. Here a
# runtime directory is the better fit and the reasoning is in
# internal/httpapi/console.go — the short version is that this image already
# reads the SPA's own settings at runtime from /srv/console/config.js
# (window.__ENV__) so one built image targets several deployments, that an embed
# behind a build tag is a code path `go test` never compiles, and that embedding
# would require the Docker build to write dist/ into its own source tree.
#
# VERSION is stamped into the binary (config.AppVersion, via -ldflags -X) as well
# as into the OCI label, so `/api/v1/capabilities` and the boot log report the
# same version the image tag advertises.
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

# -X stamps the release version into the binary, so the boot log, the OCI label
# and GET /api/v1/capabilities all report one value. It is a link-time constant
# rather than an environment variable on purpose: a version an operator can set
# is a version that can disagree with the binary.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w -X github.com/maintainerd/secret/internal/platform/config.AppVersion=$VERSION" \
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

# The console directory the Go process serves from. Unset it to run the API
# alone (the SPA files stay in the image, unserved).
ENV CONSOLE_DIR=/srv/console

# 8092 serves the REST API AND the console; 9092 is gRPC. Neither should be
# exposed to the public internet without a TLS-terminating edge in front — this is
# a vault. The unguarded routes on 8092 are /healthz, /readyz, the self-guarded
# /api/v1/setup wizard, the anonymous /api/v1/capabilities probe, and the console's
# static files.
EXPOSE 8092 9092

# Generous start-period: the service loads the root key, connects to Postgres and
# runs schema migrations in-process before it starts answering.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=5 \
    CMD curl -fsS http://localhost:8092/healthz >/dev/null || exit 1

USER m9d

# tini is PID 1: reaps zombies and forwards SIGTERM to the service, which drains
# the gRPC and HTTP servers and stops the rotator before exiting.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/secretd"]
