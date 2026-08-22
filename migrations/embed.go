// Package migrations embeds the goose SQL migrations so the schema ships inside
// the binary and can be applied on boot without the migration files on disk. The
// SQL here is the single source of truth for the store's shape: sqlc parses these
// same files to generate internal/storage, so a column added to a migration and a
// column the Go code believes in cannot drift apart.
//
// Migrations are create-only. There are no ALTER files in this repo — a table's
// create migration is edited in place while the schema is under development,
// because development databases are recreated rather than migrated forward.
package migrations

import "embed"

// FS holds every migration in this directory, in goose's numeric order.
var (
	//go:embed *.sql
	FS embed.FS
)
