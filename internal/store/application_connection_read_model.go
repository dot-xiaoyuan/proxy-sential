package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type applicationConnectionCursor struct {
	WrittenAt    string `json:"written_at"`
	SensorID     string `json:"sensor_id"`
	CampusID     string `json:"campus_id"`
	ConnectionID string `json:"connection_id"`
}

// Changed connections are rebuilt from their indexed latest-event revisions,
// so duplicates and reclassification cannot inflate counters or leave old app
// associations. Only this background cursor is serialized, never HTTP reads.
func (s *DBStore) updateApplicationConnectionReadModel(ctx context.Context) (bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO application_connection_read_model_v2_cursor(id) VALUES(1) ON CONFLICT DO NOTHING`); err != nil {
		return false, err
	}
	var raw []byte
	var cursor applicationConnectionCursor
	if err = tx.QueryRowContext(ctx, `SELECT cursor_document FROM application_connection_read_model_v2_cursor WHERE id=1 FOR UPDATE`).Scan(&raw); err != nil {
		return false, err
	}
	if err = json.Unmarshal(raw, &cursor); err != nil {
		return false, err
	}
	where := "1"
	if cursor.WrittenAt != "" {
		where = "(l.written_at,l.sensor_id,l.campus_id,l.connection_id)>(parseDateTime64BestEffort(" + chQuote(cursor.WrittenAt) + ",9)," + chQuote(cursor.SensorID) + "," + chQuote(cursor.CampusID) + "," + chQuote(cursor.ConnectionID) + ")"
	}
	query := `SELECT concat(replaceOne(toString(l.written_at),' ','T'),'Z') AS written_at,sensor_id,campus_id,connection_id FROM application_recognized_connection_dirty_log l WHERE ` + where + ` ORDER BY l.written_at,l.sensor_id,l.campus_id,l.connection_id LIMIT 1500 SETTINGS max_threads=1 FORMAT JSONEachRow`
	raw, err = s.ch.query(ctx, query)
	if err != nil {
		return false, err
	}
	var rows []applicationConnectionCursor
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return false, err
	}
	if len(rows) == 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE application_connection_read_model_v2_cursor SET updated_at=now() WHERE id=1`); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	keys := make([]string, 0, len(rows))
	seen := map[string]bool{}
	for _, r := range rows {
		key := "(" + chQuote(r.SensorID) + "," + chQuote(r.CampusID) + "," + chQuote(r.ConnectionID) + ")"
		if !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	var revision uint64
	if err = tx.QueryRowContext(ctx, `SELECT nextval('application_connection_summary_revision_seq')`).Scan(&revision); err != nil {
		return false, err
	}
	query = applicationConnectionRebuildSQL(revision, keys)
	if err = s.ch.exec(ctx, query); err != nil {
		return false, err
	}
	raw, err = json.Marshal(rows[len(rows)-1])
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE application_connection_read_model_v2_cursor SET cursor_document=$1,updated_at=$2::timestamptz WHERE id=1`, raw, rows[len(rows)-1].WrittenAt); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func applicationConnectionRebuildSQL(revision uint64, keys []string) string {
	// The v2 source uses 64-row marks, so the explicit primary-key PREWHERE is
	// applied before FINAL. This preserves reclassification semantics in one
	// aggregation pass without the former per-event argMax stage.
	return fmt.Sprintf(`INSERT INTO application_connection_summaries_v2(sensor_id,campus_id,connection_id,first_seen,last_seen,events,revision)
SELECT sensor_id,campus_id,connection_id,min(timestamp) AS first_seen,max(timestamp) AS last_seen,
 groupArray(tuple(timestamp,ip,target_id,target_type,name,category,upload_bytes,download_bytes,event_id)) AS events,toUInt64(%d) AS revision
FROM application_connection_observations_v2 FINAL
PREWHERE timestamp>=now64(9)-INTERVAL 7 DAY AND (sensor_id,campus_id,connection_id) IN (%s)
GROUP BY sensor_id,campus_id,connection_id
SETTINGS max_threads=4,max_block_size=2048,min_insert_block_size_rows=65536,min_insert_block_size_bytes=8388608,max_memory_usage=536870912,max_bytes_before_external_group_by=67108864,max_execution_time=20,async_insert=0`, revision, strings.Join(keys, ","))
}

// Drain is used before cutover and in replay tests; interactive requests never
// drain history. Every committed batch is restartable and idempotent.
func (s *DBStore) DrainApplicationConnectionReadModel(ctx context.Context) error {
	for {
		more, err := s.updateApplicationConnectionReadModel(ctx)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
}

func (s *DBStore) RunApplicationConnectionReadModel(ctx context.Context) {
	for ctx.Err() == nil {
		var upstreamLagSeconds float64
		lagErr := s.pg.db.QueryRowContext(ctx, `SELECT EXTRACT(EPOCH FROM now()-COALESCE(
 NULLIF(job->>'available_to','')::timestamptz,
 NULLIF(job->>'from','')::timestamptz,
 now())) FROM application_processing_jobs WHERE lane='realtime'`).Scan(&upstreamLagSeconds)
		if lagErr == nil && upstreamLagSeconds > 90 {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				continue
			}
		}
		batchCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		more, err := s.updateApplicationConnectionReadModel(batchCtx)
		cancel()
		delay := time.Second
		if err != nil {
			fmt.Fprintf(os.Stderr, "application connection read model failed: %v\n", err)
			delay = 5 * time.Second
		} else if more {
			// The fine-grained lookup model bounds each random key to small marks.
			// A short admission gap retains API headroom while allowing backlog
			// recovery faster than the live dirty-connection stream.
			delay = 100 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *DBStore) RunRealtimeReadModels(ctx context.Context) {
	go s.RunApplicationObservationReadModel(ctx)
	go s.RunApplicationConnectionReadModel(ctx)
	s.RunActivityV3Realtime(ctx)
}

func (s *DBStore) RunApplicationReadModels(ctx context.Context) {
	go s.RunActivityChartReadModel(ctx)
	go s.RunApplicationObservationReadModel(ctx)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.pg.WarmEndpointRecognitionCatalog(ctx)
			}
		}
	}()
	s.RunApplicationConnectionReadModel(ctx)
}
