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

	sdkauthz "github.com/maintainerd/sdk/authz"
	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/api"
	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/dynamic"
	"github.com/maintainerd/secret/internal/grpcserver"
	"github.com/maintainerd/secret/internal/httpapi"
	"github.com/maintainerd/secret/internal/leader"
	"github.com/maintainerd/secret/internal/platform/config"
	"github.com/maintainerd/secret/internal/platform/database"
	"github.com/maintainerd/secret/internal/platform/logging"
	mw "github.com/maintainerd/secret/internal/platform/middleware"
	"github.com/maintainerd/secret/internal/platform/permissions"
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
		"version", config.AppVersion,
		"app_env", config.AppEnv,
		"mode", config.DescribeMode(),
		"grpc_port", config.GRPCAddr,
		"http_port", config.HTTPAddr,
		// TWO DIFFERENT AXES, printed side by side so the log itself says they are
		// not the same setting: config_source is where this process READ its own
		// secret-valued configuration (SECRET_PROVIDER), root_key_provider is what
		// WRAPS every data key in the vault (SECRET_ROOT_KEY_PROVIDER). A deployment
		// legitimately runs aws_secrets for one and aws_kms for the other.
		"config_source", config.DescribeSecretSource(),
		"root_key_provider", config.RootKeyProvider,
	)
	logRunMode()

	// config owns the assembly, rather than this call listing fields inline. The four
	// AES fields were listed here once, and adding the KMS providers silently made that
	// list incomplete: the cloud settings arrived zero-valued, so every KMS provider
	// failed its own settings check no matter how the operator configured it. A single
	// accessor cannot drift from the variables it reads.
	rootKey, err := crypto.NewRootKeyProvider(config.RootKeyProviderConfig())
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
	guard, err := sdkauthz.Resolve(ctx, sdkauthz.Config{
		JWKSURL:         config.AuthJWKSURL,
		Issuer:          config.AuthIssuer,
		Audience:        config.AuthAudience,
		Development:     config.IsDevelopment(),
		Service:         permissions.ServiceName,
		DevOpenWarnings: permissions.DevOpenWarnings(),
	}, permissions.Map())
	if err != nil {
		return fmt.Errorf("resolve authorization: %w", err)
	}
	// The denial body follows this API's envelope on the REST surface; httpapi wires
	// that onto its own copy of the guard (see httpapi.NewServer). gRPC denials are
	// statuses and need no writer.
	guard.LogBanner()

	auditor, err := audit.New(svc)
	if err != nil {
		return err
	}

	var notifier api.Notifier
	var redriver *webhook.Redriver
	if config.WebhooksEnabled {
		// The INLINE half. Its retry budget is measured in milliseconds because it runs
		// on the write path; anything it cannot deliver is handed to the durable loop
		// below by parking the delivery row, not by holding the write open.
		redriveDelay := time.Duration(0)
		if config.WebhookRedriveEnabled {
			redriveDelay = config.WebhookRedriveBaseBackoff
		}
		notifier = webhook.New(svc, webhook.Options{
			Enabled:     true,
			Concurrency: config.WebhookConcurrency,
			// The same bounds the API applies at registration, applied again at
			// delivery. A stored row can carry a larger value than the API would
			// accept today, and a delivery runs inline on a secret write.
			MaxTimeout:   time.Duration(config.WebhookMaxTimeoutSeconds) * time.Second,
			MaxAttempts:  int32(config.WebhookMaxAttempts),
			RedriveDelay: redriveDelay,
		})

		// The DURABLE half — see internal/webhook/redrive.go. It is constructed even
		// when disabled so the log line below states which it is; Enabled() gates the
		// loop.
		redriver = webhook.NewRedriver(svc, webhook.RedriveOptions{
			Enabled:     config.WebhookRedriveEnabled,
			Interval:    config.WebhookRedriveInterval,
			Batch:       config.WebhookRedriveBatch,
			MaxAttempts: int32(config.WebhookRedriveMaxAttempts),
			BaseBackoff: config.WebhookRedriveBaseBackoff,
			MaxBackoff:  config.WebhookRedriveMaxBackoff,
			MaxTimeout:  time.Duration(config.WebhookMaxTimeoutSeconds) * time.Second,
		})
		if config.WebhookRedriveEnabled {
			slog.Info("webhook re-drive enabled",
				"interval", config.WebhookRedriveInterval.String(),
				"batch", config.WebhookRedriveBatch,
				"max_attempts", config.WebhookRedriveMaxAttempts,
				"backoff", config.WebhookRedriveBaseBackoff.String()+" doubling to "+config.WebhookRedriveMaxBackoff.String(),
				"detail", "a delivery that fails inline is retried durably and marked permanently failed once the budget is spent")
		} else {
			slog.Warn("webhook re-drive is DISABLED — a delivery that fails inline is never retried",
				"effect", "a consumer that missed a rotation notification keeps using a replaced credential until it polls",
				"variable", "SECRET_WEBHOOK_REDRIVE_ENABLED")
		}
	}

	appSvc, err := api.New(svc, auditor, notifier, api.Options{
		ReferenceMaxDepth: config.ReferenceMaxDepth,
		DefaultTenant:     config.DefaultTenant,
		// The outbound seam dynamic credentials run their DDL through. Without it
		// store.IssueDynamicLease has nothing to provision with and the issue surface
		// answers 503 — which is the documented contract, but it means dynamic secrets
		// are configurable and unusable, so the wiring is not optional.
		//
		// Zero timeouts take the package defaults, which are argued where they are
		// declared (short, because provisioning is a handful of DDL statements against a
		// database normally in the same network, and neither a request nor a reaper tick
		// may be held open by a target that has gone away).
		Provisioner: dynamic.NewPgProvisioner(0, 0),
	})
	if err != nil {
		return err
	}

	// THE REAPER, which is what makes a dynamic credential actually short-lived.
	//
	// Issuing one creates a real PostgreSQL role. The lease row says when it must stop
	// existing, but a row expiring does not drop a role — this loop is the only thing
	// that does. Leaving it unwired is invisible: every issue and every read keeps
	// working while abandoned accounts accumulate against the target database forever.
	//
	// Leader-gated like the rotator and the re-driver, and here the gate matters for a
	// second reason beyond duplicated work: two replicas revoking the same lease means
	// the loser runs a DROP ROLE for an account already gone and records a failure for
	// a lease that was correctly closed, which is indistinguishable in the audit trail
	// from a revocation that genuinely did not happen.
	reaper := dynamic.NewReaper(appSvc, dynamic.ReaperOptions{
		Enabled:  config.DynamicReaperEnabled,
		Interval: config.DynamicReaperInterval,
		Batch:    config.DynamicReaperBatch,
	})
	if config.DynamicReaperEnabled {
		slog.Info("dynamic credential reaper enabled",
			"interval", config.DynamicReaperInterval.String(),
			"batch", config.DynamicReaperBatch,
			"detail", "expired dynamic leases are revoked against their target database and closed")
	} else {
		slog.Warn("dynamic credential reaper is DISABLED — issued credentials will outlive their leases",
			"effect", "an expired lease leaves a live PostgreSQL role that nothing will drop",
			"variable", "SECRET_DYNAMIC_REAPER_ENABLED")
	}

	setupSvc, err := setup.New(svc, auditor, setup.Options{
		BootstrapToken:      config.SetupBootstrapToken,
		Development:         config.IsDevelopment(),
		DefaultTenant:       config.DefaultTenant,
		DefaultProject:      config.DefaultProject,
		DefaultEnvironment:  config.DefaultEnvironment,
		DeclaredPermissions: permissions.DeclaredPermissions(),
		// In core mode the REST wizard is shut from the first boot: the operator has
		// declared that a controller owns first-run, and two open paths is a race
		// whose winner owns the vault.
		CoreAttached: config.Mode == config.ModeCore,
	})
	if err != nil {
		return err
	}

	secretAPI := grpcserver.New(appSvc, setupSvc, config.SetupBootstrapToken, config.IsDevelopment(), config.DefaultTenant)
	setupAPI := grpcserver.NewSetupServer(setupSvc)

	// LEADER ELECTION, resolved before the workers that depend on it.
	//
	// Every request surface in this service is safe on N replicas. The BACKGROUND
	// work is not: two replicas ticking the rotator find the same due secret and
	// rotate it twice — two versions, two webhook fan-outs, and a consumer holding a
	// value that is already superseded. So the periodic work runs on exactly one
	// replica, chosen by a PostgreSQL advisory lock (see internal/leader for why an
	// advisory lock rather than a lease table).
	var elector *leader.Elector
	if config.LeaderElectionEnabled {
		elector = leader.New(leader.NewPgLocker(pool), leader.Options{})
		slog.Info("leader election enabled",
			"lock", elector.Name(), "lock_key", elector.Key(),
			"detail", "background workers run on the replica that holds this advisory lock")
	}

	// ONE LIMITER FOR BOTH TRANSPORTS. A per-transport budget is not a budget: a
	// client that has spent its reveal allowance over REST would otherwise open a gRPC
	// channel and spend another one. Both surfaces reach the same secrets with the
	// same grants, so they share a counter keyed by the same principal.
	//
	// AND ONE BUDGET ACROSS REPLICAS, for the same reason one step out: a per-process
	// counter on N replicas is N times the configured ceiling, and the reveal ceiling
	// is the exfiltration bound on a compromised token. The shared budget is metered
	// through the PostgreSQL this service already requires — no new dependency in
	// front of the reveal path — and it reserves slices rather than counting per
	// request, so it costs no round trip on the hot path. Full protocol and
	// trade-offs: internal/platform/middleware/rate_limit.go.
	var limiter *mw.Limiter
	var rateLimitStore *mw.PgReservationStore
	if config.RateLimitEnabled {
		limiter = mw.NewLimiter(config.RateLimitWindow)
		if config.RateLimitShared {
			rateLimitStore = mw.NewPgReservationStore(pool)
			// ctx, not context.Background(): a reservation in flight when SIGTERM
			// arrives is cancelled with the rest of the process rather than
			// outliving the drain.
			limiter.WithStore(ctx, rateLimitStore)
		}
		scope := "per-replica (counters are per-process; with N replicas the effective ceiling is N times these numbers)"
		if limiter.IsShared() {
			scope = "shared across replicas (postgres-backed reservations; degrades to per-replica if the database is unreachable)"
		}
		slog.Info("rate limiting enabled",
			"window", config.RateLimitWindow.String(),
			"reveal_per_window", config.RateLimitReveal,
			"write_per_window", config.RateLimitWrite,
			"setup_per_window", config.RateLimitSetup,
			"scope", scope)
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
	//
	// THE STREAM INTERCEPTOR IS NOT OPTIONAL. grpc-go dispatches unary and streaming
	// calls through different chains, so a server that installs only the unary one
	// leaves every server-streaming and bidi RPC unguarded — no token, no permission,
	// no allowlist. maintainerd.secret.v1 has no streaming RPC today, which is exactly
	// why that hole was invisible; wiring it now means the first one added arrives
	// guarded instead of open.
	grpcOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			grpcserver.RecoveryUnaryInterceptor(),
			grpcserver.AuthUnaryInterceptor(guard),
			grpcserver.RateLimitUnaryInterceptor(limiter, grpcserver.RateLimitOptions{
				Reveal: config.RateLimitReveal,
				Write:  config.RateLimitWrite,
				Setup:  config.RateLimitSetup,
			}),
		),
		grpc.ChainStreamInterceptor(
			grpcserver.AuthStreamInterceptor(guard),
		),
	}

	// TRANSPORT SECURITY, INSTALLED BEFORE THE SERVER EXISTS.
	//
	// The interceptors above prove what a caller is ALLOWED to do. Mutual TLS decides
	// whether a caller reaches an interceptor at all — and on this listener that
	// matters more than usual, because SetupService is here: the RPC through which
	// maintainerd-core provisions this vault and records itself as controller. A
	// bearer token asserts "I am core"; a verified client certificate proves it.
	//
	// config has already refused the combinations that cannot be served safely (a
	// partial set in any environment; no material at all in core mode outside
	// development), so a nil credential here means "config decided plaintext is
	// permissible for this run", not "the material failed to load" — that is an error
	// and returns below.
	creds, err := grpcserver.ServerCredentials(grpcserver.TLSOptions{
		CertFile:     config.GRPCTLSCertFile,
		KeyFile:      config.GRPCTLSKeyFile,
		ClientCAFile: config.GRPCClientCAFile,
	})
	if err != nil {
		return err
	}
	if creds != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
		slog.Info("grpc listener: mutual TLS enabled",
			"client_auth", "RequireAndVerifyClientCert",
			"min_version", "TLS 1.2",
			"cipher_policy", "ECDHE key exchange, AEAD bulk encryption only (no CBC, no static RSA)",
			"client_ca", config.GRPCClientCAFile)
	} else {
		slog.Warn("grpc listener: serving WITHOUT TLS",
			"acceptable_only_if", "a service mesh or sidecar terminates mTLS in front of this process",
			"to_enable", "SECRET_GRPC_CERT_FILE, SECRET_GRPC_KEY_FILE, SECRET_GRPC_CA_FILE")
	}

	gs := grpc.NewServer(grpcOpts...)
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
		// leader.Wrap, NOT a bare `elector`. Assigning a nil *Elector to this
		// interface field would produce a non-nil interface holding a nil pointer,
		// IsLeader would answer false, and the rotator would silently never run —
		// the exact opposite of what disabling election is meant to do. Wrap
		// collapses the nil pointer to a nil interface, which means "no election".
		Leader: leader.Wrap(elector),
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
		// The anonymous capability probe's static half. The issuer and audience are
		// handed over unconditionally and PUBLISHED only when the guard actually
		// resolved to enforced (see internal/httpapi/capabilities.go), so a leftover
		// pair in a dev-open instance's environment is never advertised as verified.
		Capabilities: httpapi.CapabilityInfo{
			Version:      config.AppVersion,
			RunMode:      config.Mode,
			AuthIssuer:   config.AuthIssuer,
			AuthAudience: config.AuthAudience,
		},
		// Serving the console from this process. Empty in development (it runs under
		// vite there); set by the release image, which bakes the built SPA at
		// /srv/console. config has already proved the path is servable.
		ConsoleDir: config.ConsoleDir,
	})
	// The REST server owns its own limiter instance by default; replace it with the
	// shared one so the two transports spend one budget.
	restServer.UseLimiter(limiter)
	// The console's directory handle is released on the way out. Deferred here rather
	// than after server.Run so it also covers an early return below.
	defer func() { _ = restServer.Close() }()
	if config.ConsoleDir != "" {
		slog.Info("serving the console from this process",
			"dir", config.ConsoleDir,
			"detail", "mounted at / outside the guarded /api/v1 group, with an index.html fallback for SPA deep links")
	}

	timeouts := serverTimeouts{
		ReadHeader:  config.HTTPReadHeaderTimeout,
		Read:        config.HTTPReadTimeout,
		Write:       config.HTTPWriteTimeout,
		Idle:        config.HTTPIdleTimeout,
		Shutdown:    config.ShutdownTimeout,
		TLSCertFile: config.HTTPTLSCertFile,
		TLSKeyFile:  config.HTTPTLSKeyFile,
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
		// The election campaign. Also never an error: a replica that cannot reach the
		// database to campaign is a FOLLOWER, which is the safe answer — refusing to
		// serve secrets because this process could not decide who runs the background
		// work would turn a degradation into an outage. Run resigns on the way out,
		// so SIGTERM releases the lock and a surviving replica is promoted
		// immediately rather than after PostgreSQL notices a dead backend.
		func(c context.Context) error {
			if elector != nil {
				elector.Run(c)
			}
			return nil
		},
		// Leader-only maintenance of the shared rate-limit table.
		func(c context.Context) error {
			runRateLimitPruner(c, leader.Wrap(elector), rateLimitStore, config.RateLimitWindow)
			return nil
		},
		// The durable webhook re-drive loop, leader-gated through the SAME election the
		// rotator and the pruner use — so a backlog is drained by one replica at a
		// steady rate rather than by all of them at once.
		//
		// Correctness does not actually depend on the gate: the claim query is
		// FOR UPDATE SKIP LOCKED and leases each row before attempting it, so the
		// worker cannot double-post even with election disabled or misconfigured. The
		// gate is about not multiplying the outbound request rate by the replica count.
		func(c context.Context) error {
			runWebhookRedrive(c, leader.Wrap(elector), redriver)
			return nil
		},
		// The dynamic-credential reaper, on the leader only. Never an error, for the
		// rotator's reason: a pass that could not reach a target database is an ordinary
		// condition that retries next tick, and taking the vault down over it would turn
		// one unreachable target into a total outage.
		func(c context.Context) error {
			runDynamicReaper(c, leader.Wrap(elector), reaper)
			return nil
		},
	)
}

// runDynamicReaper revokes expired dynamic credentials on the leader.
//
// Wired through leader.RunPeriodic like the re-driver and the pruner, so the loop's
// operational contract — a recovered panic, a non-fatal error, a logged leadership
// transition — is the shared one rather than a fourth hand-written ticker. Reaper.Run
// has its own ticker for standalone use; RunPeriodic is what adds the gate.
func runDynamicReaper(ctx context.Context, election leader.Election, reaper *dynamic.Reaper) {
	if reaper == nil || !reaper.Enabled() {
		return
	}
	// Tick returns nothing: it already recovers its own panic and logs its own outcome,
	// and there is no failure here that should stop the loop. The adapter says so
	// explicitly rather than letting a future reader assume an error was dropped.
	leader.RunPeriodic(ctx, election, "dynamic-reaper", reaper.Interval(), func(c context.Context) error {
		reaper.Tick(c)
		return nil
	})
}

// runWebhookRedrive runs the durable webhook retry loop on the leader.
//
// It is wired through leader.RunPeriodic — the same helper the rate-limit pruner uses
// — so the loop's operational contract (a recovered panic, a non-fatal error, a logged
// leadership transition) is the shared one rather than a second hand-written ticker.
func runWebhookRedrive(ctx context.Context, election leader.Election, redriver *webhook.Redriver) {
	if redriver == nil || !redriver.Enabled() {
		return
	}
	leader.RunPeriodic(ctx, election, "webhook-redrive", redriver.Interval(), redriver.Tick)
}

// rateLimitPrunerRetentionWindows is how many closed windows of bucket rows are kept
// before the pruner deletes them.
//
// Ten rather than one, and the margin is the point: the limiter never reads a closed
// window, so a kept row is pure waste — but DELETING a window some replica still
// considers live would hand out its budget twice. Ten windows is far beyond any clock
// skew worth worrying about and still bounds the table to minutes of history.
const rateLimitPrunerRetentionWindows = 10

// rateLimitPrunerMinInterval floors the pruning cadence, so a deployment running a
// very short rate-limit window does not turn the pruner into a busy loop.
const rateLimitPrunerMinInterval = 30 * time.Second

// runRateLimitPruner deletes closed rate-limit windows, on the leader only.
//
// EVERY REPLICA COULD SAFELY RUN THIS — deleting expired rows is idempotent — so the
// gate is not about correctness but about cost: N replicas issuing the same DELETE is
// N times the write load and N times the vacuum churn for exactly one result. It is
// wired through leader.RunPeriodic, which is the same helper any other background
// worker in this service should adopt (webhook re-drive, a lease reaper, version
// retention) to become multi-replica-safe.
func runRateLimitPruner(ctx context.Context, election leader.Election, store *mw.PgReservationStore, window time.Duration) {
	if store == nil {
		// No shared store: no table, nothing to prune.
		return
	}
	interval := 2 * window
	if interval < rateLimitPrunerMinInterval {
		interval = rateLimitPrunerMinInterval
	}
	retention := time.Duration(rateLimitPrunerRetentionWindows) * window

	leader.RunPeriodic(ctx, election, "rate-limit-bucket-pruner", interval, func(c context.Context) error {
		deleted, err := store.Prune(c, time.Now().Add(-retention))
		if err != nil {
			return err
		}
		if deleted > 0 {
			slog.Debug("rate limit buckets pruned", "rows", deleted, "older_than", retention.String())
		}
		return nil
	})
}

// logRunMode states, at boot, which world this instance is running in and — in
// standalone — exactly which Auth it will accept tokens from.
//
// The issuer and audience are the two values that decide whether a token minted
// by the operator's Auth is accepted by this process, and they are the two an
// operator most often gets subtly wrong (a trailing slash on the issuer, the
// resource API's name instead of its identifier). Printing them where the reader
// is already looking turns "every call is 401" from an afternoon into a glance.
// Neither is a secret: both appear in every token this service verifies. The
// client SECRET and the private key path are never logged; the two client IDs are
// public identifiers and are.
func logRunMode() {
	if config.Mode == config.ModeCore {
		slog.Info("run mode: core-attached",
			"detail", "maintainerd-core provisions this instance through the gRPC SetupService; "+
				"the REST setup wizard refuses")
		return
	}
	slog.Info("run mode: standalone",
		"detail", "this instance owns its own identity wiring; the REST setup wizard is the bootstrap path",
		"auth_issuer", orNotSet(config.AuthIssuer),
		"auth_audience", orNotSet(config.AuthAudience),
		"auth_jwks_url", orNotSet(config.AuthJWKSURL),
		"client_id", orNotSet(config.ClientID),
		"client_auth", clientAuthMethod(),
		"console_client_id", orNotSet(config.ConsoleClientID))
}

func orNotSet(v string) string {
	if v == "" {
		return "(not set)"
	}
	return v
}

// clientAuthMethod names HOW this service authenticates itself to Auth, without
// disclosing the credential either way.
func clientAuthMethod() string {
	switch {
	case config.ClientPrivateKeyFile != "":
		return "private_key_jwt"
	case config.ClientSecret != "":
		return "client_secret"
	default:
		return "(not set)"
	}
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
func readinessChecks(pool *pgxpool.Pool, guard sdkauthz.Guard) []httpapi.ReadinessCheck {
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
				if guard.Mode == sdkauthz.ModeUnavailable {
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
