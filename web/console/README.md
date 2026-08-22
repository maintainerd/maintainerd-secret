# maintainerd-secret console

The vault's own dashboard. maintainerd-secret is **adoptable alone** — an
organization can run just it plus maintainerd-auth — so it ships a console of its
own rather than a page inside maintainerd's core console.

React 19 + Vite + TypeScript (strict) + Tailwind v4 + Radix, TanStack Query for
server state, TanStack Table for listings, react-hook-form + zod for forms.

---

## Design lineage

**This console follows maintainerd-auth's console.** Auth is the first completed
app, and its console is the house design language every other maintainerd console
matches — the same shell, the same spacing and type scale, the same colour tokens
and dark mode, the same tables, dialogs, forms and empty states.

The component library under `src/components` is auth's, copied rather than
imported (the two are separate repos and separate deployables). Where a component
was auth-domain-specific, the *pattern* came over and the domain did not:

| Here | From auth | Adaptation |
|---|---|---|
| `components/ui/*` | `components/ui/*` | Byte-identical shadcn primitives. `calendar.tsx` not carried over — no date-picker surface here. |
| `components/layout/PrivateLayout` | `layout/PrivateLayout` | Same brand bar + sidebar + `max-w-6xl` column. Adds the permanent guard-open banner. |
| `components/layout/LoginLayout` | `layout/LoginLayout` | Same brand-over-card front door, minus the tenant-supplied legal links. |
| `components/navigation/AppTopNav` | `navigation/AppTopNav` | Same slate-950 bar. Tenant switcher → scope switcher; no profile fetch (see *Authentication*); adds a guard-mode chip. |
| `components/navigation/ScopeSwitcher` | `navigation/TenantSwitcher` | Same ghost combobox + command list, applied twice — secret's scope is a *pair*. |
| `components/sidebar/*` | `sidebar/*` | `NavMain` verbatim; `constants.tsx` is secret's nav. |
| `components/brand/BrandLockup` | `brand/BrandLockup` | Tenant-logo branch → the official maintainerd assets (below). |
| `components/theme/ConsoleBrandingProvider` | `theme/ConsoleBrandingProvider` | Same `useLayoutEffect`-before-paint contract; source is a fixed brand + the OS colour scheme instead of a tenant's branding record. |
| `components/data-table/*` | `data-table/*` | Toolbar, table, pagination, row actions and empty states verbatim. **`useServerDataTable` → `useClientDataTable`** (see below). |
| `components/details/*`, `card/*`, `container/*`, `badges/*` | same | Verbatim. |
| `components/form/*`, `components/inputs/*` | same | Verbatim, minus the email / phone / password-policy / file-upload / date fields. `FormSubmitButton` gains a `form` prop, because almost every form here lives in a dialog whose actions sit outside the `<form>`. |
| `components/dialog/*` | `dialog/*` | `ConfirmationDialog` + `DeleteConfirmationDialog` verbatim; `CreateTenantDialog` is auth's domain. |
| `components/ConfirmDialog` | `dialog/ConfirmationDialog` | Same dialog with a **ReactNode** description — the confirmations here run to two paragraphs. |

### Deliberately not adopted

- **`useServerDataTable`.** Auth's engine maps search and sort onto API params
  because every auth list endpoint accepts them. Secret's do not: `GET /secrets`,
  `/audit`, `/webhooks` and `/projects` take `page` and `limit` and nothing else.
  Wiring auth's engine to them would render a sortable header and a search box
  that send parameters the service silently drops — worse than no control, because
  the operator reads "no matches" and believes it. `useClientDataTable` narrows the
  fetched page in the browser instead, and the audit page says so on screen.
- **`styles/console-theme.css`.** Auth's runtime tenant-branding stylesheet. There
  is no branding API here to feed it. The `data-console-*` / `data-md-*` styling
  hooks are still on the components, so the file can be dropped in unchanged if
  secret ever grows one.
- **Redux (`store/`).** Auth uses it for the auth + tenant slices. This console's
  cross-cutting state is a token (module-level, never persisted) and a scope
  (React context), so a store would be ceremony.
- **yup.** Auth validates with yup; this console already used zod and the field
  components are resolver-agnostic.
- **`ResourceListing` on the audit page.** Its single search box would look like
  it searched the whole trail. The audit page composes the same primitives with
  its own filter row and an alert stating the limit.

---

## Branding

The official assets live in `public/` and are wired through `BrandLockup` and
`ConsoleBrandingProvider`, the way auth wires a tenant's logo:

| Asset | Where |
|---|---|
| `maintainerd-logo.svg` | Sign-in and the first-run wizard (`LoginLayout`) — the full lockup. |
| `maintainerd-icon.svg` / `maintainerd-icon-dark.svg` | The bootstrap splash. The provider picks the variant matching `prefers-color-scheme`. |
| `maintainerd-mark.svg` | The slate brand bar, inlined by `components/icon/MaintainerdMark` — a transparent mark, because a white app-icon plate reads as a sticker on a dark bar. The label drops below `sm`, leaving the mark alone. |
| `favicon.svg` | `index.html`, re-asserted by the provider. |

The app renders as **Maintainerd Secret** everywhere (`components/theme/consoleBranding.ts`).
Light/dark follows the operator's OS preference; there is no in-app toggle, so the
console never disagrees with the rest of their desktop and nothing extra is stored.

---

## What it does

| Surface | Route | Notes |
|---|---|---|
| Folder tree + secret browser | `/browse` | **Metadata only.** Key, description, tags, version, rotated-at, expires-at. Folder tree, breadcrumb, create/move folder, imports. |
| Secret detail | dialog | Overview, version history, rotation. Never a route — see *The rules*. |
| Reveal | dialog | Explicit, per-secret, audited. Value behind a click, copy-to-clipboard, reference chain shown. |
| Create / new version / edit metadata | dialog | Value input is a password field with a show toggle; base64-encoded on the wire. Metadata edits use an endpoint that cannot change a value. |
| Version history + rollback | dialog tab | Rollback appends a version rather than rewriting history, and the confirm says so. |
| Rotation | dialog tab | View/set the policy (interval + random generator), and rotate now (random or supplied). |
| Projects | `/projects` | Create, list, delete. Slugs are permanent — they are MRN segments. |
| Environments | `/projects/:slug` | Per project, ordered by position. |
| Webhooks | `/webhooks` | Per-project endpoint CRUD. The signing key is shown once. |
| Deliveries | `/webhooks/:endpointUuid` | Recent deliveries — MRN + version, never a value. |
| Deleted / recovery | `/deleted` | Restore, or destroy permanently (type-to-confirm). |
| Audit log | `/audit` | Filterable; reveals and reference hops are visually distinct. |
| Setup wizard | `/setup` | First-run standalone provisioning against `POST /api/v1/setup`. |

---

## The rules this console holds

These are not stylistic. Each one exists because the alternative turns a single
audited read into an unbounded number of unaudited ones.

1. **A list never fetches a value.** Everything on the browse screen comes from
   `GET /secrets`, whose response type has no value field. Revealing is a separate
   call behind a separate grant (`secret:GetSecret` vs `secret:ReadMetadata`).
   Asserted in `pages/browse/BrowsePage.test.tsx`.
2. **A revealed value lives in memory only.** It is held in React state inside
   `components/secrets/RevealDialog.tsx` and nowhere else — not localStorage, not
   sessionStorage, not the TanStack Query cache (the reveal is a mutation with
   `gcTime: 0` for exactly that reason). It is dropped on close and on navigation.
3. **Reveal is visibly marked as audited.** The dialog opens with a destructive
   alert saying the read wrote a row naming the operator, before the value appears.
4. **A secret's address never enters a URL.** Secret detail is a dialog, not a
   route, because a route would put the address in browser history, the referer
   header, and every proxy log in between. The same reason the service made reveal
   a `POST`. The browse listing is also given no `urlKey`, so a searched-for key
   name is not mirrored into the query string either.
5. **The setup gate fails closed.** An unreadable `/setup/status` is treated as
   NOT set up (`data?.completed ?? false`), so the wizard is the landing surface
   rather than a full console pointed at a vault that may not exist.
6. **401 → login, 403 → an in-place "not permitted" state.** Metadata access and
   value access are separate grants, so a 403 means "you are signed in and lack
   this" — bouncing it to identity would loop forever. `components/layout/states.tsx`,
   asserted in its test.
7. **The access token is never persisted.** See *Authentication*.
8. **Nothing logs a request or response body.** A put body carries a plaintext and
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
- **No profile is fetched.** There is no userinfo call, so the session menu says
  what it can honestly say — that a session is held, in memory only — rather than
  inventing a display name the way auth's top nav can.
- **Continuity across a reload is a silent re-authorization**: on boot the app
  runs a `prompt=none` authorization in a hidden iframe. While the identity SSO
  session is alive the operator sees nothing; once it is gone they land on a
  visible sign-in. A 401 from any API call takes the same path.

### Guard-open mode

If `VITE_OAUTH_ISSUER_URL`, `VITE_OAUTH_TOKEN_URL` and `VITE_OAUTH_CLIENT_ID` are
**all** absent, the console runs without a bearer token and shows a permanent,
non-dismissible banner plus a "Guard open" chip in the brand bar. That matches a
service running with `APP_ENV=development` and no
`AUTH_JWKS_URL`/`AUTH_ISSUER`/`AUTH_AUDIENCE`, whose guard serves every caller as
a blanket-granted principal. It is the local-dev posture and must never be pointed
at a production vault.

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
npm install
npx tsc --noEmit   # or: npm run build
npm run build
npm run lint
npm test
```

---

## Layout

```
src/
  auth/               PKCE flow, in-memory token store, session gate, route guard
  components/
    badges/           status pill + system badge          [auth]
    brand/            BrandLockup                          [auth, retargeted]
    card/             InformationCard, SettingsCard        [auth]
    container/        DetailsContainer                     [auth]
    data-table/       toolbar, table, pagination, row actions, empty states
                      [auth] + useClientDataTable (secret's engine)
    details/          DetailLayout, DetailHeaderCard, DetailTabs, EmptyState,
                      ListingItemCard, ListSkeleton        [auth]
    dialog/           Confirmation + type-to-confirm delete [auth]
    form/  inputs/    the field standard (FieldShell + Form*Field) [auth]
    header/           FormPageHeader                        [auth]
    icon/             MaintainerdMark (inline official mark)
    layout/           PrivateLayout, LoginLayout, PageContainer, PageHeader,
                      ProtectedShell, AppLoadingScreen, states
    navigation/       AppTopNav, ScopeSwitcher              [auth patterns]
    secrets/          folder tree, breadcrumb, reveal, detail, rotation,
                      imports, forms                       (secret's domain)
    sidebar/          AppSideBar, NavMain, constants        [auth]
    theme/            ConsoleBrandingProvider + the brand record
    ui/               vendored shadcn primitives (not linted, not hand-authored)
  context/            project/environment scope
  hooks/              one per resource, wrapping TanStack Query
  lib/                base64, folder-path arithmetic, dates, query client,
                      validations
  pages/              one directory per route; columns + dialogs under components/
  services/api/       typed client + one module per API resource
  styles/             toast.css                            [auth]
```

`services/api/types.ts` mirrors the Go domain types in the service's
`internal/store` and `internal/api` field-for-field. When the API changes, that
file changes first.

---

## Known API gaps

Noted here rather than worked around silently:

- **List endpoints page but do not search or sort.** `GET /secrets`, `/audit`,
  `/webhooks` and `/projects` accept only `page` and `limit`, so search, filters
  and sortable headers operate on the fetched page. This is why
  `useClientDataTable` exists instead of auth's `useServerDataTable`, and why the
  audit page carries an alert saying so.
- **`SecretMeta` carries no `value_type`.** Whether a secret is a `reference` is
  read from its current version via `GET /secrets/versions`, so the browse list
  cannot flag references without a second call per row — it does not, and the flag
  appears in the detail dialog instead.
- **There is no "get one webhook endpoint" route.** The endpoint detail page picks
  it out of the project's list, which the shell has usually already cached.
- **There is no unauthenticated capability endpoint.** The console cannot ask the
  service whether its guard is enforced or open, so guard-open mode is inferred
  from the absence of identity configuration rather than discovered.
