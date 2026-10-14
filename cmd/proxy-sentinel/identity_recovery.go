package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"proxy-sentinel/internal/store"
	"syscall"
)

func runIdentityRecovery(args []string) error {
	fs := flag.NewFlagSet("identity-recovery", flag.ContinueOnError)
	source := fs.String("source", "", "exact identity source")
	sensor := fs.String("sensor-id", "", "exact sensor")
	apply := fs.Bool("apply", false, "import retained failed facts after live inbox catches up")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *sensor == "" {
		return fmt.Errorf("--source and --sensor-id required")
	}
	pg, err := store.NewPostgresStore(store.PostgresOptions{DSN: os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")})
	if err != nil {
		return err
	}
	defer pg.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, err := pg.RecoverFailedIdentityBatches(ctx, *source, *sensor, *apply)
	if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil {
		return encodeErr
	}
	return err
}
