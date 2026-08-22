# maintainerd-secret console

The vault's own dashboard. maintainerd-secret is **adoptable alone** — an
organization can run just it plus maintainerd-auth — so it ships a console of its
own rather than a page inside maintainerd's core console.

React 19 + Vite + TypeScript (strict) + Tailwind v4 + Radix, TanStack Query for
server state, react-hook-form + zod for forms. The same stack as the auth and core
consoles.

---

## What it does

| Surface | Notes |
|---|---|
| Projects & environments | Create, list, delete. Slugs are permanent — they are MRN segments. |
| Folder tree + secret browser | Navigate the materialized path inside an environment; breadcrumb, create folder, move folder. |
| Secrets list | **Metadata only.** Key, description, tags, version, rotated-at, expires-at. |
| Reveal | Explicit, per-secret, audited. Value behind a click, copy-to-clipboard, reference chain shown. |
| Create / update secret | Value input is `type=password` with a show toggle; base64-encoded on the wire. |
| Version history | List versions, reveal one, roll back (with a dialog explaining it appends rather than rewrites). |
| Rotation | View/set the policy (interval + random generator), and rotate now (random or supplied). |
| References & imports | A reference secret is flagged and its resolved chain shown; a folder's imports are managed in place. |
| Webhooks | Per-project endpoint CRUD plus recent deliveries. The signing key is shown once. |
| Audit log | Filterable; reveals and reference hops are visually distinct. |
| Setup wizard | First-run standalone provisioning against `POST /api/v1/setup`. |

---

## The rules this console holds

These are not stylistic. Each one exists because the alternative turns a single
audited read into an unbounded number of unaudited ones.

1. **A list never fetches a value.** Everything on the browse screen comes from
   `GET /secrets`, whose response type has no value field. Revealing is a separate
   call behind a separate grant (`secret:GetSecret` vs `secret:ReadMetadata`).
2. **A revealed value lives in memory only.** It is held in React state inside
   `components/secrets/RevealDialog.tsx` and nowhere else — not localStorage, not
   sessionStorage, not the TanStack Query cache (the reveal is a mutation with
   `gcTime: 0` for exactly that reason). It is dropped on close and on navigation.
3. **A secret's address never enters a URL.** Secret detail is a dialog, not a
   route, because a route would put the address in browser history, the referer
   header, and every proxy log in between. This is the same reason the service
   made reveal a `POST`.
4. **The access token is never persisted.** See "Authentication" below.
5. **Nothing logs a request or response body.** A put body carries a plaintext and
   a reveal response carries one; the API client and the error boundary print
   statuses and messages only.

---

## Authentication

OAuth2 **authorization code + PKCE** against the maintainerd-auth hosted identity
app. The console is a **public client** — no client secret — and the access token
it receives is sent as a bearer to maintainerd-secret's own `/api/v1`, which
verifies it against Auth's JWKS, issuer and audience.

- **No token is stored anywhere.** It lives in a module-level variable
  (`src/auth/tokenStore.ts`) for the lifetime of the page.
- **No refresh token is requested.** An administrative surface must not hold a
  long-lived credential, so `offline_access` is never asked for.
- **Continuity across a reload is a silent re-authorization**: on boot the app
  runs a `prompt=none` authorization in a hidden iframe. While the identity SSO
  session is alive the operator sees nothing; once it is gone they land on a
  visible sign-in. A 401 from any API call takes the same path.

### Guard-open mode

If `VITE_OAUTH_ISSUER_URL`, `VITE_OAUTH_TOKEN_URL` and `VITE_OAUTH_CLIENT_ID` are
**all** absent, the console runs without a bearer token and shows a permanent,
non-dismissible banner saying so. That matches a service running with
`APP_ENV=development` and no `AUTH_JWKS_URL`/`AUTH_ISSUER`/`AUTH_AUDIENCE`, whose
guard serves every caller as a blanket-granted principal. It is the local-dev
posture and must never be pointed at a production vault.

A *partial* identity configuration is treated as none, deliberately: it would
otherwise send the operator to an authorize endpoint whose code can never be
exchanged.

### The OAuth client it expects

Register a client in maintainerd-auth with:

- grant type `authorization_code`, PKCE **required** (`S256`), **public** (no secret)
- redirect URI `https://<console-host>/auth/callback`
- post-logout redirect URI `https://<console-host>`
- scopes `openid profile email`
- an audience matching the service's `AUTH_AUDIENCE`

The permissions a signed-in user actually has come from their grants in Auth
(`secret:ReadMetadata`, `secret:GetSecret`, `secret:PutSecret`, …), not from what
this console requests.

---

## Environment

Every variable can be set at **build** time (`.env`, `import.meta.env`) or at
**run** time (`window.__ENV__`, written by `public/config.js`), so one built image
can target several deployments. None of them is a secret.

| Variable | Default | Purpose |
|---|---|---|
| `VITE_SECRET_API_BASE_URL` | `/api/v1` | Where secret's REST API lives. Same-origin by default. |
| `VITE_OAUTH_ISSUER_URL` | — | Hosted identity origin; `/authorize` and `/end-session` hang off it. |
| `VITE_OAUTH_TOKEN_URL` | — | Absolute URL of the OAuth token endpoint on Auth's public API. |
| `VITE_OAUTH_CLIENT_ID` | — | This console's public client id. |
| `VITE_OAUTH_AUDIENCE` | — | The resource-API audience secret enforces. |
| `VITE_OAUTH_SCOPE` | — | Extra scopes beyond `openid profile email`. |

Copy `.env.example` to `.env` to set them locally.

---

## Run it

### Through the dev stack (what you normally want)

```bash
cd ../../../maintainerd-dev
./maintainerd up --profile=all -d
```

Then open **https://console.secret.maintainerd.local**. nginx serves the Vite dev
server at `/` and proxies `/api/` to `m9d-secret:8092`, so the SPA talks to the API
same-origin. Hot reload works through the bind mount.

### Standalone

```bash
npm install
npm run dev      # http://localhost:3000
```

The dev server proxies `/api` to `https://console-api.secret.maintainerd.local`,
so the dev stack still has to be up for the API half to answer.

### Gates

```bash
npx tsc --noEmit   # or: npm run build
npm run build
npm run lint
npm test
```

---

## Layout

```
src/
  auth/          PKCE flow, in-memory token store, session gate, route guard
  components/
    layout/      shell, scope switcher, page header, loading/empty/error states
    secrets/     folder tree, breadcrumb, reveal, detail, rotation, imports, forms
    ui/          vendored shadcn primitives (not linted, not hand-authored)
  context/       project/environment scope
  hooks/         one per resource, wrapping TanStack Query
  lib/           base64, folder-path arithmetic, dates, query client
  pages/         one directory per route
  services/api/  typed client + one module per API resource
```

`services/api/types.ts` mirrors the Go domain types in the service's
`internal/store` and `internal/api` field-for-field. When the API changes, that
file changes first.

---

## Known API gaps

Noted here rather than worked around silently:

- **`GET /audit` pages but does not filter.** It accepts only `page` and `limit`,
  so the audit page's action / actor / resource / date filters narrow the fetched
  page and nothing more. The UI states this on screen.
- **`SecretMeta` carries no `value_type`.** Whether a secret is a `reference` is
  read from its current version via `GET /secrets/versions`, so the browse list
  cannot flag references without a second call per row — it does not, and the flag
  appears in the detail dialog instead.
- **There is no unauthenticated capability endpoint.** The console cannot ask the
  service whether its guard is enforced or open, so guard-open mode is inferred
  from the absence of identity configuration rather than discovered.
