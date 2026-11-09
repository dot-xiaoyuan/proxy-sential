package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// requeueCurrentEndpoints marks current endpoints for recognition in bounded
// batches. A fingerprint catalog update only changes the rules, not stored
// evidence, so existing endpoints must be re-evaluated explicitly. The dirty
// log is the same bounded path live observations use; history is untouched.
func requeueCurrentEndpoints(ctx context.Context, db *sql.DB, batchSize, limit int, pause time.Duration) (int, error) {
	if batchSize < 1 || batchSize > 5000 {
		return 0, fmt.Errorf("batch size must be between 1 and 5000")
	}
	if limit < 0 {
		return 0, fmt.Errorf("limit must not be negative")
	}
	last, total := "", 0
	for {
		size := batchSize
		if limit > 0 && limit-total < size {
			size = limit - total
		}
		if size <= 0 {
			return total, nil
		}
		rows, err := db.QueryContext(ctx, `SELECT endpoint_id FROM endpoint_entities WHERE endpoint_id>$1 ORDER BY endpoint_id LIMIT $2`, last, size)
		if err != nil {
			return total, err
		}
		ids := make([]string, 0, size)
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return total, err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return total, err
		}
		if len(ids) == 0 {
			return total, nil
		}
		payload, err := json.Marshal(ids)
		if err != nil {
			return total, err
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO endpoint_recognition_dirty_log(endpoint_id) SELECT value FROM jsonb_array_elements_text($1::jsonb)`, payload); err != nil {
			return total, err
		}
		total += len(ids)
		last = ids[len(ids)-1]
		if len(ids) < size || (limit > 0 && total >= limit) {
			return total, nil
		}
		if pause > 0 {
			select {
			case <-ctx.Done():
				return total, ctx.Err()
			case <-time.After(pause):
			}
		}
	}
}

func runRecognition(args []string) error {
	if len(args) < 1 || args[0] != "requeue" {
		return fmt.Errorf("usage: proxy-sentinel recognition requeue --postgres-dsn <dsn> [--batch-size 2000] [--limit 0] [--pause 2s] [--dry-run]")
	}
	fs := flag.NewFlagSet("recognition requeue", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	batchSize := fs.Int("batch-size", 2000, "endpoints per batch (1..5000)")
	limit := fs.Int("limit", 0, "maximum endpoints to enqueue, 0 enqueues all current endpoints")
	pause := fs.Duration("pause", 2*time.Second, "pause between batches")
	dryRun := fs.Bool("dry-run", false, "count current endpoints without enqueueing")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *postgresDSN == "" {
		return fmt.Errorf("--postgres-dsn is required")
	}
	if *batchSize < 1 || *batchSize > 5000 || *limit < 0 {
		return fmt.Errorf("invalid batch size or limit")
	}
	db, err := sql.Open("pgx", *postgresDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if *dryRun {
		var total int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_entities`).Scan(&total); err != nil {
			return err
		}
		fmt.Printf("current endpoints: %d (dry run)\n", total)
		return nil
	}
	total, err := requeueCurrentEndpoints(ctx, db, *batchSize, *limit, *pause)
	if err != nil {
		return err
	}
	fmt.Printf("enqueued %d current endpoints for recognition\n", total)
	return nil
}
