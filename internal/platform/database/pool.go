// Package database owns the Postgres connection pool and the migration runner.
// It is the only package that knows how this service reaches its storage; the
// store speaks to *storage.Queries and never to a DSN.
package database

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maintainerd/secret/internal/platform/config"
)

// NewPool opens a pgx pool, applies pool limits, and waits for the database to
// become reachable before returning. Mirrors core's pool (core
// internal/platform/database/pool.go).
//
// SSL is enforced outside development. A secret store that ships ciphertext and
// wrapped DEKs over a plaintext socket has moved the problem, not solved it: an
// observer on the wire sees the same bytes the disk holds.
func NewPool(ctx context.Context) (*pgxpool.Pool, error) {
	if !config.IsDevelopment() && config.DBSSLMode == "disable" {
		return nil, fmt.Errorf("database SSL is disabled (DB_SSLMODE=disable), which is not allowed outside %s", config.EnvDevelopment)
	}

	poolCfg, err := pgxpool.ParseConfig(config.GetDBConnectionString())
	if err != nil {
		return nil, fmt.Errorf("parse database config: %w", err)
	}
	poolCfg.MaxConns = int32(config.DBMaxOpenConns)
	poolCfg.MinConns = int32(config.DBMaxIdleConns)
	poolCfg.MaxConnLifetime = time.Duration(config.DBConnMaxLifetimeSec) * time.Second
	poolCfg.MaxConnIdleTime = time.Duration(config.DBConnMaxIdleSec) * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}

	if err := waitForDatabase(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	slog.Info("database connected (pgx pool)",
		"max_conns", config.DBMaxOpenConns,
		"min_conns", config.DBMaxIdleConns,
		"conn_max_lifetime_sec", config.DBConnMaxLifetimeSec,
		"conn_max_idle_sec", config.DBConnMaxIdleSec,
		"statement_timeout_ms", config.DBStatementTimeoutMs,
		"sslmode", config.DBSSLMode,
	)
	return pool, nil
}

// waitForDatabase retries the first connection with linear backoff. The database
// and this service usually start together, so a cold start racing Postgres is the
// normal case, not an error.
func waitForDatabase(ctx context.Context, pool *pgxpool.Pool) error {
	const attempts = 10
	delay := 2 * time.Second

	var lastErr error
	for i := 1; i <= attempts; i++ {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		lastErr = pool.Ping(pingCtx)
		cancel()
		if lastErr == nil {
			return nil
		}
		if i == attempts {
			break
		}
		slog.Warn("waiting for postgres", "attempt", i, "of", attempts, "retry_in", delay.String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("connect to database after %d attempts: %w", attempts, lastErr)
}
