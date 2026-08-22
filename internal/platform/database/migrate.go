package database

import (
	"context"
	"database/sql"
	"fmt"

	// Registers the "pgx" database/sql driver goose needs. goose wants a
	// database/sql handle; the rest of the service uses the pgx pool directly.
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/maintainerd/secret/internal/platform/config"
	"github.com/maintainerd/secret/migrations"
)

// RunMigrations applies every pending embedded migration. Same approach as core
// (core internal/platform/database/migrate.go): a short-lived database/sql
// connection just for goose, independent of the query pool.
//
// Migrations run on boot rather than as a separate deploy step so that a fresh
// install and an upgrade are the same operation, and so the schema the binary was
// built against is the schema it runs on.
func RunMigrations(ctx context.Context) error {
	sqlDB, err := sql.Open("pgx", config.GetDBConnectionString())
	if err != nil {
		return fmt.Errorf("open migration connection: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.UpContext(ctx, sqlDB, "."); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}
