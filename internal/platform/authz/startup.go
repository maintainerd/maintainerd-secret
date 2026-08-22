package authz

import (
	"context"
	"log/slog"
	"strings"

	sdkauth "github.com/maintainerd/sdk/auth"
)

// Config is the auth wiring resolved from the environment at boot.
type Config struct {
	// JWKSURL, Issuer and Audience are Auth's public key endpoint and the two
	// checks that make a token this service's token rather than merely a
	// well-formed one. All three are required for enforcement.
	JWKSURL  string
	Issuer   string
	Audience string
	// Development permits the reduced-safety open mode.
	Development bool
}

// Resolve decides the guard posture and builds the verifier.
//
// The ladder is the whole point, and it has exactly three rungs:
//
//	fully configured                  -> ModeEnforced
//	unconfigured, development         -> ModeDevOpen  (with a loud banner)
//	unconfigured, anything else       -> ModeUnavailable
//
// There is no fourth rung where a partially configured service guesses. A JWKS URL
// without an issuer or audience check is a service that accepts any token signed by
// Auth for anyone — including tokens minted for a different audience entirely — so
// a partial configuration is treated as no configuration.
//
// An error is returned ONLY when the configuration is present but unusable (the
// JWKS endpoint cannot be prepared). That is a genuine boot failure: the operator
// asked for enforcement and it cannot be provided, and silently downgrading to open
// or unavailable would either expose the vault or hide a typo.
func Resolve(ctx context.Context, cfg Config) (Guard, error) {
	jwks := strings.TrimSpace(cfg.JWKSURL)
	issuer := strings.TrimSpace(cfg.Issuer)
	audience := strings.TrimSpace(cfg.Audience)

	if jwks != "" && issuer != "" && audience != "" {
		v, err := sdkauth.NewVerifier(ctx, jwks, issuer, audience)
		if err != nil {
			return Guard{}, err
		}
		return Guard{Mode: ModeEnforced, Verify: SDKVerify(v)}, nil
	}

	reason := missingReason(jwks, issuer, audience)
	if cfg.Development {
		return Guard{Mode: ModeDevOpen, Reason: reason}, nil
	}
	return Guard{Mode: ModeUnavailable, Reason: reason}, nil
}

// missingReason names exactly which variables are absent, because "auth is not
// configured" is the least useful possible message to an operator who has set two
// of the three.
func missingReason(jwks, issuer, audience string) string {
	var missing []string
	if jwks == "" {
		missing = append(missing, "AUTH_JWKS_URL")
	}
	if issuer == "" {
		missing = append(missing, "AUTH_ISSUER")
	}
	if audience == "" {
		missing = append(missing, "AUTH_AUDIENCE")
	}
	if len(missing) == 0 {
		return ""
	}
	return strings.Join(missing, ", ") + " not set"
}

// LogBanner announces the resolved posture at boot.
//
// The development banner names every disabled guard individually rather than saying
// "auth disabled". A one-line summary is easy to skim past in a startup log; a list
// that says "ANY caller can reveal ANY secret" is not. This is the last warning
// before an unguarded vault starts answering requests, and the intended reader is a
// human who has just changed an environment variable and is not sure what it did.
func (g Guard) LogBanner() {
	switch g.Mode {
	case ModeEnforced:
		slog.Info("authorization: ENFORCED",
			"mode", g.Mode.String(),
			"permissions", strings.Join(DeclaredPermissions(), " "))
	case ModeDevOpen:
		slog.Warn("=====================================================================")
		slog.Warn("AUTHORIZATION IS DISABLED — DEVELOPMENT MODE ONLY", "cause", g.Reason)
		slog.Warn("The following guards are OFF on this instance:")
		slog.Warn("  * bearer-token authentication — requests need no credential at all")
		slog.Warn("  * per-action permissions — every caller is treated as secret:Admin")
		slog.Warn("  * MRN scoping — no tenant, project or environment boundary is applied")
		slog.Warn("  * reveal gating — ANY caller can read ANY secret's decrypted value")
		slog.Warn("Audit rows are still written, attributed to the subject 'development-open'.")
		slog.Warn("Set AUTH_JWKS_URL, AUTH_ISSUER and AUTH_AUDIENCE to enforce.")
		slog.Warn("=====================================================================")
	default:
		slog.Error("authorization: UNAVAILABLE — the API is disabled",
			"cause", g.Reason,
			"effect", "REST answers 503 and gRPC serves health only until auth is configured")
	}
}
