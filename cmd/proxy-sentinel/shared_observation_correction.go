package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"proxy-sentinel/internal/controlplane"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func runSharedObservationCorrection(args []string) error {
	fs := flag.NewFlagSet("shared-observation-correction", flag.ContinueOnError)
	runID := fs.String("run-id", "", "stable review run ID")
	badRuleBefore := fs.String("bad-rule-before", "", "exclusive decision cutoff in RFC3339")
	receivedBefore := fs.String("received-before", "", "inclusive received cutoff in RFC3339")
	limit := fs.Int("limit", 100, "number of saved decisions to inspect (1..200)")
	apply := fs.Bool("apply", false, "append audited corrections and advance the run cursor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*apply {
		return fmt.Errorf("shared-observation-correction requires --apply; run one bounded audited batch at a time")
	}
	if *runID == "" || *badRuleBefore == "" || *receivedBefore == "" {
		return fmt.Errorf("--run-id, --bad-rule-before and --received-before are required")
	}
	badAt, err := time.Parse(time.RFC3339Nano, *badRuleBefore)
	if err != nil {
		return fmt.Errorf("parse --bad-rule-before: %w", err)
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, *receivedBefore)
	if err != nil {
		return fmt.Errorf("parse --received-before: %w", err)
	}
	dsn := os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")
	if dsn == "" {
		return fmt.Errorf("PROXY_SENTINEL_POSTGRES_DSN is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := controlplane.ReviewHistoricalSharedDecisionBatch(ctx, db, *runID, badAt, receivedAt, *limit)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
