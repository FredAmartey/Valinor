package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/server"
	"github.com/valinor-ai/valinor/internal/platform/telemetry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.Load("config.yaml")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Setup logging
	logger := telemetry.NewLogger(cfg.Log.Level, cfg.Log.Format)
	telemetry.SetDefault(logger)

	slog.Info("valinor starting",
		"version", "0.1.0",
		"port", cfg.Server.Port,
	)

	// Connect to database (optional for startup — will retry)
	ctx := context.Background()
	var pool *database.Pool

	if cfg.Database.URL != "" {
		slog.Info("connecting to database")
		p, err := database.Connect(ctx, cfg.Database.URL, cfg.Database.MaxConns)
		if err != nil {
			slog.Warn("database connection failed, starting without DB", "error", err)
		} else {
			pool = p
			defer pool.Close()

			// Run migrations
			migrationsURL := fmt.Sprintf("file://%s", cfg.Database.MigrationsPath)
			if err := database.RunMigrations(cfg.Database.URL, migrationsURL); err != nil {
				return fmt.Errorf("running migrations: %w", err)
			}
			slog.Info("migrations complete")
		}
	}

	// Create and start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := server.New(addr, pool)

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("server ready", "addr", addr)
	return srv.Start(ctx)
}
