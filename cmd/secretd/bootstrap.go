package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/maintainerd/kit/log"
	"github.com/maintainerd/kit/server"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/grpcserver"
	"github.com/maintainerd/secret/internal/platform/config"
	"github.com/maintainerd/secret/internal/platform/database"
	"github.com/maintainerd/secret/internal/store"
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
	log.Setup(config.LogLevel)
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

	api := grpcserver.New(svc, config.SetupBootstrapToken, config.IsDevelopment())
	gs := server.NewGRPC(func(g *grpc.Server) { secretv1.RegisterSecretServiceServer(g, api) })
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.Healthz())

	return server.Run(ctx,
		func(c context.Context) error { return server.ServeGRPC(c, config.GRPCAddr, gs) },
		func(c context.Context) error { return server.ServeHTTP(c, config.HTTPAddr, mux) },
	)
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
