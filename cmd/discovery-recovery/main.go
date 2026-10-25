// Explicit, bounded recovery queue migration. Dry-run unless --apply is given.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"proxy-sentinel/internal/discovery"
	"time"
)

func main() {
	id := flag.String("recovery-id", "", "immutable recovery manifest ID")
	cutoff := flag.String("cutoff", "", "exclusive original admission cutoff in RFC3339")
	limit := flag.Int("limit", 500, "maximum batches per transaction (1..500)")
	apply := flag.Bool("apply", false, "move one bounded page; default only reports eligible totals")
	status := flag.Bool("status", false, "read the bounded consumer and queue status without moving tasks")
	cancelOld := flag.Bool("cancel-old", false, "audit and cancel old unprocessed discovery work instead of moving lanes")
	flag.Parse()
	at, err := time.Parse(time.RFC3339Nano, *cutoff)
	if !*status && err != nil {
		fmt.Fprintln(os.Stderr, "valid RFC3339 cutoff required")
		os.Exit(2)
	}
	if *status && *apply {
		fmt.Fprintln(os.Stderr, "status cannot be combined with apply")
		os.Exit(2)
	}
	db, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "database configuration failed")
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if *status {
		out, err := (discovery.Repository{DB: db}).PipelineStatus(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "status unavailable:", discovery.WorkErrorCode(err))
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	var out discovery.RecoveryMove
	if *cancelOld {
		out, err = (discovery.Repository{DB: db}).CancelRecovery(ctx, *id, at, *limit, *apply)
	} else {
		out, err = (discovery.Repository{DB: db}).MoveRecovery(ctx, *id, at, *limit, *apply)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "recovery failed:", discovery.WorkErrorCode(err))
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}
