# Contributing to Maintainerd Secret

Thanks for contributing! This document covers the basics.

## DCO

All contributions are accepted under the Apache-2.0 license. You certify you have the right to submit your contribution by including a `Signed-off-by:` line in your commits (`git commit -s`).

## Branch & commit conventions

- Branch from `main` with a descriptive branch name (e.g. `feat/folder-move`, `fix/rewrap-resume`).
- Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `perf:`).
- Keep commits small and focused — one logical change per commit.

## Workspace layout

`go.mod` `replace`s `github.com/maintainerd/kit` and `github.com/maintainerd/sdk` with the sibling checkouts `../maintainerd-kit` and `../maintainerd-sdk`. Clone all three next to each other or nothing builds. CI reproduces this by checking the siblings out into `.deps/` and repointing the replaces — if you add a new workspace-local `replace`, add it to **every** Go job in `.github/workflows/` too.

## Quality gates

Before opening a PR, run:

```bash
make check          # gofmt + go vet + staticcheck + tests
make test-race      # the suite as CI runs it
make proto-lint     # buf lint
go mod tidy
```

And for the console:

```bash
cd web/console
npm ci
npm run lint
npm test
npm run build       # tsc -b && vite build — this is the type-check gate
```

CI blocks merge if any of these fail.

## Running the stack locally

See the [README](README.md) Run section, or use `maintainerd-dev/` Docker Compose:

```bash
cd ../maintainerd-dev
./maintainerd up --profile=all -d
```

## Building the production image

The image build needs the workspace siblings inside its build context:

```bash
make docker-build   # docker-prep stages ../maintainerd-{kit,sdk} into .deps/, then builds
```

See the header of [`Dockerfile`](Dockerfile) for the full rationale and for the console-serving wiring that is still outstanding.

## Database migrations

Migrations are **create-only** while the schema is pre-release: edit the original `NNN_create_*.sql` in place rather than adding an `ALTER`. Development databases are recreated, not migrated forward, and a test enforces this. After changing a migration or a query, run `make sqlc` so `internal/storage` and the schema cannot drift apart.

## Security-sensitive changes

This is a vault. Changes to `internal/crypto`, `internal/platform/permissions`, `internal/store` or anything touching key material, audit records or the guard get extra scrutiny — explain the threat model in the PR description. Never add a code path that can log, marshal or return a plaintext value or a DEK.

Enforcement itself lives in the SDK (`github.com/maintainerd/sdk/authz`), shared with every other maintainerd service; this repo owns only the permission vocabulary and the surface table in `internal/platform/permissions`. **Adding a route or an RPC means deciding its permission there.** The table is an allowlist, so an unmapped surface is denied to every caller, and the gap-audit test (`internal/platform/permissions/audit_test.go`) walks the live chi router and the live gRPC service descriptors and fails until you have. An **exemption** — a surface served with no permission check at all — additionally needs a written justification in that test file, and reviewers should treat one as the highest-scrutiny change in this repo.

## Getting help

Open an issue or start a discussion on the [GitHub repository](https://github.com/maintainerd/maintainerd-secret).
