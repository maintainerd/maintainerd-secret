// Runtime configuration placeholder.
//
// A single built image targets a different API / identity origin per deployment
// by having this file regenerated at container start. The empty defaults here
// let the app fall back to build-time import.meta.env values during local dev.
//
// Nothing here is a secret: the console is a PUBLIC OAuth client (authorization
// code + PKCE) and has no client secret.
window.__ENV__ = {
  VITE_SECRET_API_BASE_URL: "",
  VITE_OAUTH_ISSUER_URL: "",
  VITE_OAUTH_TOKEN_URL: "",
  VITE_OAUTH_CLIENT_ID: "",
  VITE_OAUTH_AUDIENCE: "",
  VITE_OAUTH_SCOPE: ""
};
