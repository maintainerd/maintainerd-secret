package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/maintainerd/kit/server"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/grpcserver"
	"github.com/maintainerd/secret/internal/httpapi"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/platform/config"
	"github.com/maintainerd/secret/internal/platform/database"
	"github.com/maintainerd/secret/internal/platform/logging"
	mw "github.com/maintainerd/secret/internal/platform/middleware"
	"github.com/maintainerd/secret/internal/rotator"
	"github.com/maintainerd/secret/internal/setup"
	"github.com/maintainerd/secret/internal/store"
	"github.com/maintainerd/secret/internal/webhook"
)

// run boots the secret service.
//
// The order below is the order the dependencies actually require, and every step is
// a hard gate — a secret store that comes up in a partially working state is worse
// than one that refuses to start, because it will accept writes it cannot honour
// later:
//
//  1. Config, validated. A bad retention or pool value fails here, not on first use.
//  2. The ROOT KEY. Before the database, because there is no point connecting to a
//     store this process cannot decrypt. Outside development an absent or malformed
//     key is fatal — never a generated one.
//  3. The database, then migrations.
//  4. Registration of the active root key in root_keys, which must precede the first
//     write: secret_versions.kek_id is a foreign key to it.
//  5. The default scope, so a standalone install has somewhere to put a secret.
func run(parent context.Context) error {
	if err := config.Init(); err != nil {
		return err
	}
	// The logger is installed with the REDACTING handler wrapped around it (see
	// internal/platform/logging), so every line this process emits from here on —
	// including the boot banner, a recovered panic, and anything a future debug line
	// adds — passes through the filter that scrubs credential-named attributes.
	logging.Setup(config.LogLevel)

	// The request bounds the API layer's DTO rules read. Installed BEFORE any surface
	// is built, so there is no window in which a request is validated against the
	// defaults rather than the operator's configuration.
	api.ApplyLimits(api.Limits{
		MaxSecretValueBytes:      config.MaxSecretValueBytes,
		MaxBatchItems:            config.MaxBatchItems,
		MaxTags:                  config.MaxTags,
		MaxTagLength:             config.MaxTagLength,
		MaxPageLimit:             config.MaxPageLimit,
		MaxDescriptionLength:     config.MaxDescriptionLength,
		MaxWebhookTimeoutSeconds: config.WebhookMaxTimeoutSeconds,
		MaxWebhookAttempts:       config.WebhookMaxAttempts,
	})

	slog.Info("starting maintainerd-secret",
		"app_env", config.AppEnv,
		"grpc_port", config.GRPCAddr,
		"http_port", config.HTTPAddr,
		"root_key_provider", config.RootKeyProvider,
	)

	rootKey, err := crypto.NewRootKeyProvider(crypto.ProviderConfig{
		Provider: config.RootKeyProvider,
		AppEnv:   config.AppEnv,
		Key:      config.RootKey,
		KeyFile:  config.RootKeyFile,
	})
	if err != nil {
		return err
	}
	ring, err := crypto.NewKeyRing(rootKey)
	if err != nil {
		return err
	}
	slog.Info("root of trust loaded", "kek_id", rootKey.KeyID())

	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := database.RunMigrations(ctx); err != nil {
		return err
	}
	slog.Info("migrations applied")

	svc, err := store.NewService(store.NewPgRepository(pool), ring, store.Policy{
		KeepVersions:       int32(config.KeepVersions),
		RecoveryWindow:     config.RecoveryWindow,
		RewrapBatch:        int32(config.RewrapBatchSize),
		DefaultTenant:      config.DefaultTenant,
		DefaultProject:     config.DefaultProject,
		DefaultEnvironment: config.DefaultEnvironment,
	})
	if err != nil {
		return err
	}

	if err := registerRootKey(ctx, svc); err != nil {
		return err
	}
	if config.DefaultScopeAutocreate {
		if _, err := svc.EnsureDefaultScope(ctx); err != nil {
			return fmt.Errorf("ensure default scope: %w", err)
		}
	}

	// The auth posture is resolved BEFORE any surface is built, and its banner is
	// printed immediately, so the last thing in the boot log before the service
	// starts answering is what is or is not guarding it.
	guard, err := authz.Resolve(ctx, authz.Config{
		JWKSURL:     config.AuthJWKSURL,
		Issuer:      config.AuthIssuer,
		Audience:    config.AuthAudience,
		Development: config.IsDevelopment(),
	})
	if err != nil {
		return fmt.Errorf("resolve authorization: %w", err)
	}
	guard.LogBanner()

	auditor, err := audit.New(svc)
	if err != nil {
		return err
	}

	var notifier api.Notifier
	if config.WebhooksEnabled {
		notifier = webhook.New(svc, webhook.Options{
			Enabled:     true,
			Concurrency: config.WebhookConcurrency,
			// The same bounds the API applies at registration, applied again at
			// delivery. A stored row can carry a larger value than the API would
			// accept today, and a delivery runs inline on a secret write.
			MaxTimeout:  time.Duration(config.WebhookMaxTimeoutSeconds) * time.Second,
			MaxAttempts: int32(config.WebhookMaxAttempts),
		})
	}

	appSvc, err := api.New(svc, auditor, notifier, api.Options{
		ReferenceMaxDepth: config.ReferenceMaxDepth,
		DefaultTenant:     config.DefaultTenant,
	})
	if err != nil {
		return err
	}

	setupSvc, err := setup.New(svc, auditor, setup.Options{
		BootstrapToken:      config.SetupBootstrapToken,
		Development:         config.IsDevelopment(),
		DefaultTenant:       config.DefaultTenant,
		DefaultProject:      config.DefaultProject,
		DefaultEnvironment:  config.DefaultEnvironment,
		DeclaredPermissions: authz.DeclaredPermissions(),
	})
	if err != nil {
		return err
	}

	secretAPI := grpcserver.New(appSvc, setupSvc, config.SetupBootstrapToken, config.IsDevelopment(), config.DefaultTenant)
	setupAPI := grpcserver.NewSetupServer(setupSvc)

	// ONE LIMITER FOR BOTH TRANSPORTS. A per-transport budget is not a budget: a
	// client that has spent its reveal allowance over REST would otherwise open a gRPC
	// channel and spend another one. Both surfaces reach the same secrets with the
	// same grants, so they share a counter keyed by the same principal.
	var limiter *mw.Limiter
	if config.RateLimitEnabled {
		limiter = mw.NewLimiter(config.RateLimitWindow)
		slog.Info("rate limiting enabled (in-process, per-replica)",
			"window", config.RateLimitWindow.String(),
			"reveal_per_window", config.RateLimitReveal,
			"write_per_window", config.RateLimitWrite,
			"setup_per_window", config.RateLimitSetup,
			"caveat", "counters are per-process; with N replicas the effective ceiling is N times these numbers")
	} else {
		slog.Warn("rate limiting is DISABLED — the reveal and setup surfaces are unmetered",
			"variable", "SECRET_RATE_LIMIT_ENABLED")
	}

	// The gRPC server is built here rather than through kit's server.NewGRPC for
	// reasons the kit helper cannot express: this service needs an auth interceptor on
	// every RPC, a panic recovery interceptor (grpc-go recovers NOTHING by default, so
	// one panicking RPC would take the whole vault down), a rate limiter that shares
	// the REST budget, and it must register reflection ONLY in development. Reflection
	// enumerates every RPC and message — convenient with grpcurl on a laptop, a map of
	// the vault's API handed to anyone who can open a socket in production.
	//
	// INTERCEPTOR ORDER: recovery outermost so it also covers a panic inside auth or
	// the limiter; auth next, because the limiter keys on the verified principal; the
	// limiter last, so an unauthenticated caller is refused before it can consume
	// anyone's budget.
	gs := grpc.NewServer(grpc.ChainUnaryInterceptor(
		grpcserver.RecoveryUnaryInterceptor(),
		grpcserver.AuthUnaryInterceptor(guard),
		grpcserver.RateLimitUnaryInterceptor(limiter, grpcserver.RateLimitOptions{
			Reveal: config.RateLimitReveal,
			Write:  config.RateLimitWrite,
			Setup:  config.RateLimitSetup,
		}),
	))
	secretv1.RegisterSecretServiceServer(gs, secretAPI)
	secretv1.RegisterSetupServiceServer(gs, setupAPI)
	healthpb.RegisterHealthServer(gs, health.NewServer())
	if config.IsDevelopment() {
		reflection.Register(gs)
		slog.Warn("grpc server reflection is REGISTERED — development only",
			"effect", "every RPC and message name is enumerable by any caller that can open a socket")
	}

	rot := rotator.New(appSvc, rotator.Options{
		Enabled:  config.RotationEnabled,
		Interval: config.RotationInterval,
		Batch:    config.RotationBatch,
	})

	restServer := httpapi.NewServer(appSvc, setupSvc, guard, httpapi.Options{
		Production:       !config.IsDevelopment(),
		MaxBodyBytes:     config.HTTPMaxBodyBytes,
		RequestTimeout:   config.HTTPRequestTimeout,
		ReadinessTimeout: config.ReadinessTimeout,
		RateLimit: httpapi.RateLimitOptions{
			Enabled: config.RateLimitEnabled,
			Window:  config.RateLimitWindow,
			Reveal:  config.RateLimitReveal,
			Write:   config.RateLimitWrite,
			Setup:   config.RateLimitSetup,
		},
		Readiness: readinessChecks(pool, guard),
	})
	// The REST server owns its own limiter instance by default; replace it with the
	// shared one so the two transports spend one budget.
	restServer.UseLimiter(limiter)

	timeouts := serverTimeouts{
		ReadHeader: config.HTTPReadHeaderTimeout,
		Read:       config.HTTPReadTimeout,
		Write:      config.HTTPWriteTimeout,
		Idle:       config.HTTPIdleTimeout,
		Shutdown:   config.ShutdownTimeout,
	}

	slog.Info("serving", "shutdown_timeout", config.ShutdownTimeout.String())
	return server.Run(ctx,
		func(c context.Context) error { return serveGRPC(c, config.GRPCAddr, gs, config.ShutdownTimeout) },
		func(c context.Context) error {
			return serveHTTP(c, config.HTTPAddr, restServer.Router(), timeouts)
		},
		// The rotator runs alongside the servers and never returns an error: a
		// failing rotation pass is an ordinary condition, and taking the vault down
		// because a scheduled rotation had a bad tick would be self-defeating. Run
		// returns once the current pass finishes, so errgroup.Wait below is what makes
		// SIGTERM drain the rotator as well as the two servers.
		func(c context.Context) error { rot.Run(c); return nil },
	)
}

// readinessChecks are the dependencies /readyz gates on.
//
// TWO CHECKS, AND BOTH FAIL CLOSED:
//
//	database  a Ping. A replica that cannot reach its store can only produce errors,
//	          so it should not be receiving traffic. Note this is READINESS, not
//	          liveness — a database blip takes replicas out of rotation, it does not
//	          restart them, which is the difference between a brief degradation and a
//	          restart storm.
//	auth      the guard's posture. ModeUnavailable means auth is REQUIRED (this is not
//	          development) and not configured, which is precisely the state in which
//	          this replica must not be answering: it cannot verify a token, so it
//	          cannot authorize a reveal. ModeDevOpen is reported ready because a
//	          development instance is deliberately open and has already announced that
//	          at boot in the loudest terms the log allows.
func readinessChecks(pool *pgxpool.Pool, guard authz.Guard) []httpapi.ReadinessCheck {
	return []httpapi.ReadinessCheck{
		{
			Name: "database",
			Probe: func(c context.Context) error {
				return pool.Ping(c)
			},
		},
		{
			Name: "auth",
			Probe: func(context.Context) error {
				if guard.Mode == authz.ModeUnavailable {
					return fmt.Errorf("authorization is unavailable: %s", guard.Reason)
				}
				return nil
			},
		},
	}
}

// registerRootKey records the active key in the KEK registry and reports any
// superseded key that still has versions pointing at it.
//
// The warning is not noise. A key left in 'retiring' means a rotation was started
// and never finished: reads of those rows still depend on the old key being supplied
// at boot, so the operator needs to either finish the rewrap or keep providing the
// old key. Failing silently here is how a store ends up with rows nobody can read.
func registerRootKey(ctx context.Context, svc *store.Service) error {
	row, err := svc.EnsureActiveRootKey(ctx)
	if err != nil {
		return fmt.Errorf("register active root key: %w", err)
	}
	slog.Info("active root key registered", "kek_id", row.KekID, "provider", row.Provider)

	pending, err := svc.PendingRewrapKeys(ctx)
	if err != nil {
		return fmt.Errorf("check pending root key rewraps: %w", err)
	}
	for _, k := range pending {
		slog.Warn("superseded root key still has versions wrapped under it; a rewrap is pending",
			"kek_id", k.KekID,
			"provider", k.Provider,
			"activated_at", timeOrZero(k.ActivatedAt.Time, k.ActivatedAt.Valid))
	}
	return nil
}

func timeOrZero(t time.Time, valid bool) string {
	if !valid {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
