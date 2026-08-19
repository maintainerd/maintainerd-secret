package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"github.com/maintainerd/kit/config"
	"github.com/maintainerd/kit/log"
	"github.com/maintainerd/kit/server"
	"github.com/maintainerd/kit/setup"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
	"github.com/maintainerd/secret/internal/grpcserver"
	"github.com/maintainerd/secret/internal/store"
)

// run bootstraps the secret service entirely on the kit: shared config/log, the
// setup pattern, and the HTTP+gRPC server with health/reflection/graceful shutdown.
func run(parent context.Context) error {
	base := config.LoadBase()
	log.Setup(base.LogLevel)

	grpcAddr := config.NormalizePort(config.GetEnv("GRPC_PORT", "9092"))
	httpAddr := config.NormalizePort(config.GetEnv("HTTP_PORT", "8092"))
	slog.Info("starting maintainerd-secret", "app_env", base.AppEnv, "grpc_port", grpcAddr, "http_port", httpAddr)

	rootKey, err := loadRootKey()
	if err != nil {
		return err
	}
	st, err := store.New(rootKey)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}
	mode := setup.New(config.GetEnv("SETUP_BOOTSTRAP_TOKEN", ""))
	svc := grpcserver.New(st, mode)

	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	gs := server.NewGRPC(func(g *grpc.Server) { secretv1.RegisterSecretServiceServer(g, svc) })
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.Healthz())

	return server.Run(ctx,
		func(c context.Context) error { return server.ServeGRPC(c, grpcAddr, gs) },
		func(c context.Context) error { return server.ServeHTTP(c, httpAddr, mux) },
	)
}

// loadRootKey reads the 32-byte AES-256 root key from SECRET_ROOT_KEY, or — for
// local dev only — generates an ephemeral one. A store cannot unlock itself, so
// this key always comes from outside (env/KMS).
func loadRootKey() ([]byte, error) {
	if v := os.Getenv("SECRET_ROOT_KEY"); v != "" {
		if len(v) != 32 {
			return nil, fmt.Errorf("SECRET_ROOT_KEY must be 32 bytes (AES-256), got %d", len(v))
		}
		return []byte(v), nil
	}
	slog.Warn("SECRET_ROOT_KEY not set — generating an ephemeral key; secrets will not survive a restart")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
