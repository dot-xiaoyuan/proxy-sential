package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"proxy-sentinel/internal/store"
)

// reset-recovery is deliberately separate from fresh-cutover: an authorized
// test reset removed the mutable cursor, not the prior immutable generation.
func runRouterResetRecovery(args []string) error {
	fs := flag.NewFlagSet("router reset-recovery", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sensorID := fs.String("sensor-id", "", "sensor whose router cursor was cleared")
	resetID := fs.String("reset-id", "", "unique authorized reset identifier")
	authorizationRef := fs.String("authorization-ref", "", "reference to the authorized reset record")
	fixedCutoverText := fs.String("fixed-cutover-at", "", "original immutable cutover time in RFC3339Nano")
	fixedCancelID := fs.String("fixed-cancel-id", "", "original immutable cutover cancel ID")
	resetText := fs.String("reset-started-at", "", "authorized reset start in RFC3339Nano")
	firstText := fs.String("first-indexed-at", "", "first retained router index time in RFC3339Nano")
	firstKey := fs.String("first-event-key", "", "first retained router index key")
	firstHash := fs.String("first-sha256", "", "first retained router index content SHA256")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	clickhouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP DSN")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *sensorID == "" || *resetID == "" || *authorizationRef == "" ||
		*fixedCutoverText == "" || *fixedCancelID == "" || *resetText == "" || *firstText == "" ||
		*firstKey == "" || *firstHash == "" || *postgresDSN == "" || *clickhouseDSN == "" {
		return errors.New("router reset-recovery requires sensor, reset audit, original cutover, reset start, first retained index proof and database DSNs")
	}
	fixedAt, err := time.Parse(time.RFC3339Nano, *fixedCutoverText)
	if err != nil {
		return fmt.Errorf("parse fixed router cutover: %w", err)
	}
	resetAt, err := time.Parse(time.RFC3339Nano, *resetText)
	if err != nil {
		return fmt.Errorf("parse router reset start: %w", err)
	}
	firstAt, err := time.Parse(time.RFC3339Nano, *firstText)
	if err != nil {
		return fmt.Errorf("parse first retained router index: %w", err)
	}
	backend, err := store.NewDBStore(store.Options{
		Mode: store.ModeDB, SensorID: *sensorID, PostgresDSN: *postgresDSN,
		ClickHouseDSN: *clickhouseDSN, RequestTimeout: 70 * time.Second,
	})
	if err != nil {
		return err
	}
	defer backend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	proof, err := backend.RestoreStreamRouterAfterReset(ctx, store.StreamRouterResetRecoveryRequest{
		SensorID: *sensorID, ResetID: *resetID, AuthorizationRef: *authorizationRef,
		FixedCutoverAt: fixedAt, FixedCancelID: *fixedCancelID, ResetStartedAt: resetAt,
		ExpectedFirstIndexedAt: firstAt, ExpectedFirstEventKey: *firstKey,
		ExpectedFirstSHA256: *firstHash,
	})
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, map[string]any{
		"sensor_id": *sensorID, "reset_id": *resetID,
		"fixed_cutover_at": fixedAt.UTC(), "fixed_cancel_id": *fixedCancelID,
		"cursor_indexed_at": resetAt.UTC(), "processed_events": 0,
		"deleted_range_disposition": "authorized_reset_unprocessed", "deleted_unprocessed_rows": nil,
		"proof": proof,
	})
}
