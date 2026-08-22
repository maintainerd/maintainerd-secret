// Runtime configuration.
//
// A single built image targets a different API / identity origin per deployment
// by having this file REGENERATED at container start (or written by an init
// container, a ConfigMap, or the static host serving these files). The empty
// defaults here let the app fall back to build-time import.meta.env values
// during local dev.
//
// THE KEYS ARE THE SERVICE'S OWN VARIABLE NAMES, on purpose. An operator
// following the standalone runbook creates one console SPA client in
// maintainerd-auth and is handed one client id; they set SECRET_CONSOLE_CLIENT_ID
// once and both halves — the service, which validates it at boot, and this
// console, which signs in with it — read the same value. The VITE_* spellings
// below remain supported as build-time fallbacks and are what a local .env uses.
//
// Nothing here is a secret: the console is a PUBLIC OAuth client (authorization
// code + PKCE) and has no client secret. Do NOT put SECRET_CLIENT_SECRET or any
// other backend credential in this file — it is served to every browser.
//
// Rendered from the environment, e.g.:
//
//   cat > "$CONSOLE_DIR/config.js" <<EOF
//   window.__ENV__ = {
//     SECRET_API_BASE_URL: "${SECRET_API_BASE_URL:-}",
//     AUTH_ISSUER: "${AUTH_ISSUER:-}",
//     SECRET_CONSOLE_TOKEN_URL: "${SECRET_CONSOLE_TOKEN_URL:-}",
//     SECRET_CONSOLE_CLIENT_ID: "${SECRET_CONSOLE_CLIENT_ID:-}",
//     AUTH_AUDIENCE: "${AUTH_AUDIENCE:-}",
//     SECRET_CONSOLE_SCOPE: "${SECRET_CONSOLE_SCOPE:-}"
//   };
//   EOF
window.__ENV__ = {
  // Where secret's REST API lives. Empty means same-origin /api/v1.
  SECRET_API_BASE_URL: "",

  // The identity trio. All three are required TOGETHER: a half-configured
  // identity would send the operator to an authorize endpoint whose code can
  // never be exchanged, so the console treats it as none and runs in guard-open
  // mode instead.
  AUTH_ISSUER: "",
  SECRET_CONSOLE_TOKEN_URL: "",
  SECRET_CONSOLE_CLIENT_ID: "",

  // The resource-API audience secret enforces (the service's AUTH_AUDIENCE). The
  // token has to be minted FOR secret, or secret's verifier rejects it.
  AUTH_AUDIENCE: "",

  // Extra scopes beyond `openid profile email`.
  SECRET_CONSOLE_SCOPE: "",

  // --- build-time spellings, still honoured -----------------------------
  VITE_SECRET_API_BASE_URL: "",
  VITE_OAUTH_ISSUER_URL: "",
  VITE_OAUTH_TOKEN_URL: "",
  VITE_OAUTH_CLIENT_ID: "",
  VITE_OAUTH_AUDIENCE: "",
  VITE_OAUTH_SCOPE: ""
};
