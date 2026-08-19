package main

import (
	"context"
	"log/slog"
	"os"
)

func main() {
	if err := run(context.Background()); err != nil {
		slog.Error("maintainerd-secret failed", "error", err)
		os.Exit(1)
	}
}
