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
		recentOK := true
		closedMinute := time.Now().UTC().Truncate(time.Minute)
		for i := *lookback; i >= 1; i-- {
			minute := closedMinute.Add(-time.Duration(i) * time.Minute)
			if err := processMinute(ctx, pool, minute); err != nil {
				recentOK = false
				if !errors.Is(err, context.Canceled) {
					log.Printf("recognition-minute-shadow: minute=%s: %v", minute.Format(time.RFC3339), err)
				}
			}
		}
		if err := recheckLateMinutes(ctx, pool, *lookback); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("recognition-minute-shadow: late recheck: %v", err)
		}
		if recentOK {
			if err := processProjectedMinutes(ctx, pool, closedMinute.Add(-time.Duration(*lookback)*time.Minute)); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("recognition-minute-shadow: projected cursor: %v", err)
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
	rows, err := pool.Query(ctx, `WITH receipt AS (
 SELECT recognition_input->>'protocol' AS protocol,count(*) AS inputs,
 count(*) FILTER(WHERE (recognition_input->>'parsed')::boolean) AS parsed,
 count(*) FILTER(WHERE jsonb_array_length(COALESCE(recognition_input->'targets','[]'::jsonb))>0) AS attributed,
 count(*) FILTER(WHERE (recognition_input->>'features')::integer>0) AS features,
 count(*) FILTER(WHERE COALESCE((recognition_result->>'candidates')::integer,0)>0) AS candidates,
 count(*) FILTER(WHERE COALESCE((recognition_result->>'conclusions')::integer,0)>0) AS conclusions,
 count(*) FILTER(WHERE recognition_status='conflict') AS conflict,
 count(*) FILTER(WHERE recognition_status='processing') AS processing,
 count(*) FILTER(WHERE recognition_status IN ('unattributed','unattributed_expired')) AS unattributed,
 count(*) FILTER(WHERE recognition_status IN ('no_features','insufficient_evidence')) AS insufficient,
 count(*) FILTER(WHERE recognition_status IN ('parse_error','diagnostic_limit') OR recognition_result ? 'last_error') AS errors,
 count(*) FILTER(WHERE recognition_overdue OR (recognition_status IN ('processing','unattributed') AND accepted_at<now()-interval '5 seconds')) AS overdue,
 count(*) FILTER(WHERE recognition_result->'timings' IS NOT NULL) AS timed,
 COALESCE(avg((recognition_result->'timings'->>'read_and_prepare_ms')::double precision),0) AS read_ms,
 COALESCE(avg((recognition_result->'timings'->>'lookup_ms')::double precision),0) AS lookup_ms,
 COALESCE(avg((recognition_result->'timings'->>'rules_ms')::double precision),0) AS rules_ms,
 COALESCE(avg((recognition_result->'timings'->>'write_ms')::double precision),0) AS write_ms,
 COALESCE(percentile_cont(.95) WITHIN GROUP(ORDER BY extract(epoch FROM recognition_completed_at-accepted_at)*1000) FILTER(WHERE recognition_completed_at IS NOT NULL),0) AS p95_ms
 FROM stream_discovery_receipts
 WHERE recognition_input IS NOT NULL AND accepted_at >= $1 AND accepted_at < $1 + interval '1 minute'
 GROUP BY recognition_input->>'protocol'
), manifest AS (
 SELECT item.key AS protocol,
 sum((item.value->>'inputs')::bigint)::bigint AS inputs,
 sum((item.value->>'parsed')::bigint)::bigint AS parsed,
 0::bigint AS attributed,
 sum((item.value->>'features')::bigint)::bigint AS features,
 0::bigint AS candidates,0::bigint AS conclusions,0::bigint AS conflict,
 0::bigint AS processing,0::bigint AS unattributed,
 sum((item.value->>'insufficient')::bigint)::bigint AS insufficient,
 sum((item.value->>'errors')::bigint)::bigint AS errors,
 0::bigint AS overdue,0::bigint AS timed,
 0::double precision AS read_ms,0::double precision AS lookup_ms,
 0::double precision AS rules_ms,0::double precision AS write_ms,
 0::double precision AS p95_ms
 FROM stream_projection_segments s
 JOIN stream_discovery_segment_receipt_manifests m ON m.segment_id=s.segment_id
 CROSS JOIN LATERAL jsonb_each(m.recognition_summary) AS item(key,value)
 WHERE s.archive_receipt_mode='manifest' AND s.accepted_at >= $1
  AND s.accepted_at < $1 + interval '1 minute'
  AND s.accepted_at >= (SELECT (state->>'since')::timestamptz
   FROM read_model_runtime_state WHERE name='recognition-fresh-cutoff')
 GROUP BY item.key
), combined AS (
 SELECT * FROM receipt UNION ALL SELECT * FROM manifest
)
SELECT protocol,sum(inputs)::bigint,sum(parsed)::bigint,sum(attributed)::bigint,sum(features)::bigint,
 sum(candidates)::bigint,sum(conclusions)::bigint,sum(conflict)::bigint,sum(processing)::bigint,
 sum(unattributed)::bigint,sum(insufficient)::bigint,sum(errors)::bigint,sum(overdue)::bigint,sum(timed)::bigint,
 max(read_ms),max(lookup_ms),max(rules_ms),max(write_ms),
 max(p95_ms)
FROM combined GROUP BY protocol`, minute)
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
 minute,protocol,inputs,parsed,attributed,features,candidates,conclusions,conflict,processing,unattributed,insufficient,errors,overdue,timed,read_ms,lookup_ms,rules_ms,write_ms,p95_ms,updated_at,first_computed_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now(),now())
 ON CONFLICT(minute,protocol) DO UPDATE SET inputs=EXCLUDED.inputs,parsed=EXCLUDED.parsed,attributed=EXCLUDED.attributed,features=EXCLUDED.features,candidates=EXCLUDED.candidates,conclusions=EXCLUDED.conclusions,conflict=EXCLUDED.conflict,processing=EXCLUDED.processing,unattributed=EXCLUDED.unattributed,insufficient=EXCLUDED.insufficient,errors=EXCLUDED.errors,overdue=EXCLUDED.overdue,timed=EXCLUDED.timed,read_ms=EXCLUDED.read_ms,lookup_ms=EXCLUDED.lookup_ms,rules_ms=EXCLUDED.rules_ms,write_ms=EXCLUDED.write_ms,p95_ms=EXCLUDED.p95_ms,updated_at=now(),first_computed_at=CASE WHEN recognition_coverage_minute_shadow.first_computed_at='-infinity'::timestamptz THEN now() ELSE recognition_coverage_minute_shadow.first_computed_at END`, args...); err != nil {
			return err
		}
	}
	log.Printf("recognition-minute-shadow: minute=%s protocols=%d", minute.Format(time.RFC3339), len(list))
	return nil
}

// Revisit late acceptance minutes while recognition jobs can still settle.
// Existing older rows carry -infinity and are outside this new-start window.
func recheckLateMinutes(ctx context.Context, pool *pgxpool.Pool, lookback int) error {
	rows, err := pool.Query(ctx, `SELECT minute FROM recognition_coverage_minute_shadow
 WHERE first_computed_at>=now()-interval '10 minutes'
  AND minute<date_trunc('minute',now())-make_interval(mins=>$1)
 GROUP BY minute ORDER BY min(updated_at) LIMIT 3`, lookback)
	if err != nil {
		return err
	}
	minutes := []time.Time{}
	for rows.Next() {
		var minute time.Time
		if err = rows.Scan(&minute); err != nil {
			break
		}
		minutes = append(minutes, minute)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, minute := range minutes {
		if err := processMinute(ctx, pool, minute); err != nil {
			return err
		}
	}
	return nil
}

// The cursor is advanced only after every selected acceptance minute has
// been recalculated. Projection transactions have a two-minute retry budget;
// the extra minute fences rows whose projected_at precedes commit.
func processProjectedMinutes(ctx context.Context, pool *pgxpool.Pool, recentStart time.Time) error {
	var since time.Time
	var after string
	if err := pool.QueryRow(ctx, `SELECT (state->>'projected_at')::timestamptz,state->>'segment_id'
 FROM read_model_runtime_state WHERE name='recognition-minute-shadow-projection-cursor'`).Scan(&since, &after); err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `SELECT accepted_at,projected_at,segment_id
 FROM stream_projection_segments
 WHERE (projected_at,segment_id)>($1,$2)
  AND projected_at<now()-interval '3 minutes'
 ORDER BY projected_at,segment_id LIMIT 200`, since, after)
	if err != nil {
		return err
	}
	type projectedSegment struct {
		accepted  time.Time
		projected time.Time
		id        string
	}
	segments := []projectedSegment{}
	for rows.Next() {
		var segment projectedSegment
		if err = rows.Scan(&segment.accepted, &segment.projected, &segment.id); err != nil {
			break
		}
		segments = append(segments, segment)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	seen := map[time.Time]bool{}
	var last projectedSegment
	for _, segment := range segments {
		minute := segment.accepted.UTC().Truncate(time.Minute)
		if !minute.Before(recentStart) {
			last = segment
			continue
		}
		if !seen[minute] {
			if len(seen) == 3 {
				break
			}
			if err := processMinute(ctx, pool, minute); err != nil {
				return err
			}
			seen[minute] = true
		}
		last = segment
	}
	if last.id == "" {
		return nil
	}
	_, err = pool.Exec(ctx, `UPDATE read_model_runtime_state
 SET state=jsonb_build_object('projected_at',$1::timestamptz,'segment_id',$2::text),updated_at=now()
 WHERE name='recognition-minute-shadow-projection-cursor'`, last.projected, last.id)
	return err
}
