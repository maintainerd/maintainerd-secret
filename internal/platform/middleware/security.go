package middleware

import "net/http"

// SecurityHeaders sets the response headers this service's API always carries.
//
// THIS IS A JSON API, and the header set is chosen for that rather than copied from a
// page-serving app:
//
//   - Content-Security-Policy is `default-src 'none'; frame-ancestors 'none'`. An API
//     response has no scripts, no styles, no images and no frames, so the honest policy
//     is "nothing", and it is the one that actually protects: if a response is ever
//     rendered as a document (a browser sniffing a JSON error body, a legacy Flash-style
//     content-type confusion), nothing in it can load or execute.
//   - X-Content-Type-Options: nosniff is the other half of that. Without it a browser
//     may re-interpret an application/json body as HTML, which is how a reflected value
//     in an error message becomes XSS on an API that renders no HTML at all.
//   - X-Frame-Options: DENY duplicates frame-ancestors for the browsers that never
//     learned CSP framing. Redundant on purpose: the failure mode of the duplicate is
//     nothing, and the failure mode of relying on CSP alone is a clickjacked console.
//   - Referrer-Policy: no-referrer. Stricter than Auth's strict-origin-when-cross-origin
//     because of what a referer would carry FROM this service: a request to a secret
//     store should never announce even the origin it came from to a third party.
//   - Cache-Control: no-store on every response, not just the reveal. The reveal handler
//     sets it explicitly too (defence in depth), but the default belongs here — a
//     metadata listing naming every credential in production does not belong in a proxy
//     cache either.
//   - Strict-Transport-Security only in production, and only when the request arrived
//     over TLS or through a proxy that says it did. Sending HSTS over plaintext is
//     ignored by browsers by specification, and sending it from a dev instance on
//     localhost poisons the developer's browser for the whole domain.
//
// production comes from config.IsDevelopment() at the call site rather than being read
// from the environment here, so the posture is decided once, at boot, alongside every
// other fail-closed decision.
func SecurityHeaders(production bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy",
				"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Cache-Control", "no-store")

			if production && isTLS(r) {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isTLS reports whether the request reached the service over TLS, directly or through
// a terminating proxy.
//
// X-Forwarded-Proto is consulted here and NOWHERE else in this service — the audit
// trail's client IP deliberately ignores forwarding headers (see httpapi.clientIP)
// because a caller-chosen IP corrupts the record an incident review depends on. The
// asymmetry is intentional and the reasoning is different in each direction: a forged
// X-Forwarded-Proto: https can only cause an HSTS header to be sent to a client that
// asked for it, which is harmless, while a forged X-Forwarded-For writes an attacker's
// choice of address into audit_log, which is not.
func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}
