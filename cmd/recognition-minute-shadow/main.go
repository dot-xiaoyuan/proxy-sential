package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	dsn := flag.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	interval := flag.Duration("interval", time.Minute, "loop interval")
	lookback := flag.Int("lookback-minutes", 10, "closed minutes to recompute")
	once := flag.Bool("once", false, "run one pass and exit")
	flag.Parse()
	if strings.TrimSpace(*dsn) == "" || *lookback < 1 || *interval < 10*time.Second {
		fmt.Fprintln(os.Stderr, "recognition-minute-shadow requires postgres-dsn, lookback>=1 and interval>=10s")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "recognition-minute-shadow:", err)
		os.Exit(2)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "recognition-minute-shadow:", err)
		os.Exit(2)
	}
	run := func() {
		for i := *lookback; i >= 1; i-- {
			minute := time.Now().UTC().Truncate(time.Minute).Add(-time.Duration(i) * time.Minute)
			if err := processMinute(ctx, pool, minute); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("recognition-minute-shadow: minute=%s: %v", minute.Format(time.RFC3339), err)
			}
		}
	}
	run()
	if *once {
		return
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func processMinute(ctx context.Context, pool *pgxpool.Pool, minute time.Time) error {
	rows, err := pool.Query(ctx, `SELECT recognition_input->>'protocol',count(*),
 count(*) FILTER(WHERE (recognition_input->>'parsed')::boolean),
 count(*) FILTER(WHERE jsonb_array_length(COALESCE(recognition_input->'targets','[]'::jsonb))>0),
 count(*) FILTER(WHERE (recognition_input->>'features')::integer>0),
 count(*) FILTER(WHERE COALESCE((recognition_result->>'candidates')::integer,0)>0),
 count(*) FILTER(WHERE COALESCE((recognition_result->>'conclusions')::integer,0)>0),
 count(*) FILTER(WHERE recognition_status='conflict'),
 count(*) FILTER(WHERE recognition_status='processing'),
 count(*) FILTER(WHERE recognition_status IN ('unattributed','unattributed_expired')),
 count(*) FILTER(WHERE recognition_status IN ('no_features','insufficient_evidence')),
 count(*) FILTER(WHERE recognition_status IN ('parse_error','diagnostic_limit') OR recognition_result ? 'last_error'),
 count(*) FILTER(WHERE recognition_overdue OR (recognition_status IN ('processing','unattributed') AND accepted_at<now()-interval '5 seconds')),
 count(*) FILTER(WHERE recognition_result->'timings' IS NOT NULL),
 COALESCE(avg((recognition_result->'timings'->>'read_and_prepare_ms')::double precision),0),
 COALESCE(avg((recognition_result->'timings'->>'lookup_ms')::double precision),0),
 COALESCE(avg((recognition_result->'timings'->>'rules_ms')::double precision),0),
 COALESCE(avg((recognition_result->'timings'->>'write_ms')::double precision),0),
 COALESCE(percentile_cont(.95) WITHIN GROUP(ORDER BY extract(epoch FROM recognition_completed_at-accepted_at)*1000) FILTER(WHERE recognition_completed_at IS NOT NULL),0)
 FROM stream_discovery_receipts
 WHERE recognition_input IS NOT NULL AND accepted_at >= $1 AND accepted_at < $1 + interval '1 minute'
 GROUP BY recognition_input->>'protocol'`, minute)
	if err != nil {
		return err
	}
	type row struct {
		protocol string
		values   []any
	}
	list := []row{}
	for rows.Next() {
		var protocol string
		var inputs, parsed, attributed, features, candidates, conclusions, conflict, processing, unattributed, insufficient, errors, overdue, timed int64
		var readMS, lookupMS, rulesMS, writeMS, p95MS float64
		if err := rows.Scan(&protocol, &inputs, &parsed, &attributed, &features, &candidates, &conclusions, &conflict, &processing, &unattributed, &insufficient, &errors, &overdue, &timed, &readMS, &lookupMS, &rulesMS, &writeMS, &p95MS); err != nil {
			rows.Close()
			return err
		}
		list = append(list, row{protocol, []any{inputs, parsed, attributed, features, candidates, conclusions, conflict, processing, unattributed, insufficient, errors, overdue, timed, readMS, lookupMS, rulesMS, writeMS, p95MS}})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, item := range list {
		args := append([]any{minute, item.protocol}, item.values...)
		if _, err := pool.Exec(ctx, `INSERT INTO recognition_coverage_minute_shadow(
 minute,protocol,inputs,parsed,attributed,features,candidates,conclusions,conflict,processing,unattributed,insufficient,errors,overdue,timed,read_ms,lookup_ms,rules_ms,write_ms,p95_ms,updated_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now())
 ON CONFLICT(minute,protocol) DO UPDATE SET inputs=EXCLUDED.inputs,parsed=EXCLUDED.parsed,attributed=EXCLUDED.attributed,features=EXCLUDED.features,candidates=EXCLUDED.candidates,conclusions=EXCLUDED.conclusions,conflict=EXCLUDED.conflict,processing=EXCLUDED.processing,unattributed=EXCLUDED.unattributed,insufficient=EXCLUDED.insufficient,errors=EXCLUDED.errors,overdue=EXCLUDED.overdue,timed=EXCLUDED.timed,read_ms=EXCLUDED.read_ms,lookup_ms=EXCLUDED.lookup_ms,rules_ms=EXCLUDED.rules_ms,write_ms=EXCLUDED.write_ms,p95_ms=EXCLUDED.p95_ms,updated_at=now()`, args...); err != nil {
			return err
		}
	}
	log.Printf("recognition-minute-shadow: minute=%s protocols=%d", minute.Format(time.RFC3339), len(list))
	return nil
}
