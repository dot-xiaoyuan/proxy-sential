package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const activityChartArray = `arrayFilter(t->t.1 IN('type','source_ip') OR t.2!='',[tuple('type',type),tuple('protocol',proto),tuple('domain',multiIf(type='dns',dns_query,type='http',http_host,type='tls',sni,'')),tuple('http_host',if(type='http',http_host,'')),tuple('tls_sni',if(type='tls',sni,'')),tuple('user_agent',if(type='http',user_agent,'')),tuple('tls_fp',if(type='tls' AND ja3!='',concat('ja3:',ja3),'')),tuple('tls_fp',if(type='tls' AND ja4!='',concat('ja4:',ja4),'')),tuple('dst_port',if(dst_port=0,'',toString(dst_port))),tuple('dst_ip',dst_ip),tuple('source_ip',subject_ip),tuple('protocol_label',multiIf(type='dns','DNS',type='http','HTTP',type='tls','TLS',type='quic','QUIC',type='flow' AND proto!='',upper(proto),upper(type))),tuple('ip_domain',if(subject_ip!='' AND multiIf(type='dns',dns_query,type='http',http_host,type='tls',sni,'')!='',toJSONString(tuple(subject_ip,multiIf(type='dns',dns_query,type='http',http_host,type='tls',sni,''))),'')),tuple('ip_ja3',if(subject_ip!='' AND ja3!='',toJSONString(tuple(subject_ip,ja3)),'')),tuple('ip_ja4',if(subject_ip!='' AND ja4!='',toJSONString(tuple(subject_ip,ja4)),'')),tuple('ip_ttl',if(subject_ip!='' AND ttl>0,toJSONString(tuple(subject_ip,toString(ttl))),''))])`

type activityChartCursor struct {
	WrittenAt   string `json:"written_at"`
	WindowStart string `json:"window_start"`
	SensorID    string `json:"sensor_id"`
	CampusID    string `json:"campus_id"`
}

// Keep a contiguous receipt prefix so acknowledging its last row never skips
// work. Repeated notifications share a rebuild; distinct bucket/scope work
// remains bounded independently of the number of notifications fetched.
func activityChartReceiptPrefix(rows []activityChartCursor, maxKeys int) []activityChartCursor {
	seen := make(map[[3]string]struct{})
	for i, row := range rows {
		key := [3]string{row.WindowStart, row.SensorID, row.CampusID}
		if _, ok := seen[key]; ok {
			continue
		}
		if len(seen) >= maxKeys {
			return rows[:i]
		}
		seen[key] = struct{}{}
	}
	return rows
}

func (s *DBStore) updateActivityChartReadModel(ctx context.Context) (bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO activity_chart_read_model_cursor_v2(id) VALUES(1) ON CONFLICT DO NOTHING`); err != nil {
		return false, err
	}
	var raw []byte
	var cursor activityChartCursor
	if err = tx.QueryRowContext(ctx, `SELECT cursor_document FROM activity_chart_read_model_cursor_v2 WHERE id=1 FOR UPDATE`).Scan(&raw); err != nil {
		return false, err
	}
	if err = json.Unmarshal(raw, &cursor); err != nil {
		return false, err
	}
	where := "1"
	if cursor.WrittenAt != "" {
		where = "(activity_chart_dirty_log.written_at,activity_chart_dirty_log.window_start,sensor_id,campus_id)>(parseDateTime64BestEffort(" + chQuote(cursor.WrittenAt) + ",9),parseDateTimeBestEffort(" + chQuote(cursor.WindowStart) + ")," + chQuote(cursor.SensorID) + "," + chQuote(cursor.CampusID) + ")"
	}
	raw, err = s.ch.query(ctx, `SELECT concat(replaceOne(toString(written_at),' ','T'),'Z') AS written_at,formatDateTime(window_start,'%Y-%m-%dT%H:%i:%SZ','UTC') AS window_start,sensor_id,campus_id FROM activity_chart_dirty_log WHERE `+where+` ORDER BY activity_chart_dirty_log.written_at,activity_chart_dirty_log.window_start,sensor_id,campus_id LIMIT 1000 SETTINGS max_threads=1 FORMAT JSONEachRow`)
	if err != nil {
		return false, err
	}
	var rows []activityChartCursor
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return false, err
	}
	rows = activityChartReceiptPrefix(rows, 20)
	if len(rows) == 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE activity_chart_read_model_cursor_v2 SET updated_at=now() WHERE id=1`); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	keys := []string{}
	seen := map[string]bool{}
	var first, last time.Time
	for _, row := range rows {
		stamp, err := time.Parse(time.RFC3339Nano, row.WindowStart)
		if err != nil {
			return false, err
		}
		if first.IsZero() || stamp.Before(first) {
			first = stamp
		}
		if last.IsZero() || stamp.After(last) {
			last = stamp
		}
		key := "(parseDateTimeBestEffort(" + chQuote(row.WindowStart) + ")," + chQuote(row.SensorID) + "," + chQuote(row.CampusID) + ")"
		if !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	var revision uint64
	if err = tx.QueryRowContext(ctx, `SELECT nextval('application_connection_summary_revision_seq')`).Scan(&revision); err != nil {
		return false, err
	}
	sourceWhere := "timestamp>=parseDateTime64BestEffort(" + chQuote(first.Format(time.RFC3339Nano)) + ",6) AND timestamp<parseDateTime64BestEffort(" + chQuote(last.Add(5*time.Minute).Format(time.RFC3339Nano)) + ",6) AND (toStartOfFiveMinutes(timestamp),sensor_id,campus_id) IN(" + strings.Join(keys, ",") + ")"
	query := fmt.Sprintf(`INSERT INTO activity_chart_bucket_facts_v2 SELECT window_start,sensor_id,campus_id,dimension,value,toUInt64(0),first_seen,last_seen,toUInt64(%d) FROM activity_chart_bucket_facts_v2 FINAL WHERE (window_start,sensor_id,campus_id) IN(%s)
 UNION ALL SELECT window_start,sensor_id,campus_id,t.1 AS dimension,t.2 AS value,count() AS event_count,min(timestamp) AS first_seen,max(timestamp) AS last_seen,toUInt64(%d) AS revision FROM(SELECT timestamp,toStartOfFiveMinutes(timestamp) AS window_start,sensor_id,campus_id,arrayJoin(%s) AS t FROM normalized_event_features FINAL WHERE %s) GROUP BY window_start,sensor_id,campus_id,dimension,value SETTINGS max_threads=1,max_block_size=2048,min_insert_block_size_rows=65536,min_insert_block_size_bytes=8388608,max_memory_usage=268435456,max_bytes_before_external_group_by=134217728,max_execution_time=20,async_insert=0`, revision*2, strings.Join(keys, ","), revision*2+1, activityChartArray, sourceWhere)
	if err = s.ch.exec(ctx, query); err != nil {
		return false, err
	}
	raw, err = json.Marshal(rows[len(rows)-1])
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE activity_chart_read_model_cursor_v2 SET cursor_document=$1,updated_at=$2::timestamptz WHERE id=1`, raw, rows[len(rows)-1].WrittenAt); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	// Five-minute facts power the live views and define the receipt cursor.
	// Coarse hour/day facts are an optimization for wider windows: a timeout
	// there must not roll the live cursor back and make every subsequent pass
	// rebuild the same facts again. Raw features and five-minute facts remain
	// available for an offline coarse rebuild.
	_ = s.rebuildActivityCoarseBuckets(ctx, rows, revision)
	return true, nil
}

func (s *DBStore) DrainActivityChartReadModel(ctx context.Context) error {
	for {
		more, err := s.updateActivityChartReadModel(ctx)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
}

func (s *DBStore) RunActivityChartReadModel(ctx context.Context) {
	for {
		batchCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		more, err := s.updateActivityChartReadModel(batchCtx)
		cancel()
		delay := time.Second
		if more && err == nil {
			// Bound background rebuild pressure so continuous ingest cannot starve
			// interactive API queries. The cursor keeps catch-up restartable.
			delay = 5 * time.Second
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

func BackfillActivityChartKeys(ctx context.Context, db *sql.DB, ch *ClickHouseStore) error {
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO application_read_model_backfills(name,cursor_at,until_at,status) VALUES('activity-chart-buckets-v2',$1,$2,'running') ON CONFLICT DO NOTHING`, now.Add(-7*24*time.Hour), now); err != nil {
		return err
	}
	for {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var from, until time.Time
		var status string
		if err = tx.QueryRowContext(ctx, `SELECT cursor_at,until_at,status FROM application_read_model_backfills WHERE name='activity-chart-buckets-v2' FOR UPDATE`).Scan(&from, &until, &status); err != nil {
			tx.Rollback()
			return err
		}
		if status == "completed" {
			tx.Rollback()
			return nil
		}
		to := minTime(from.Add(time.Hour), until)
		query := fmt.Sprintf(`INSERT INTO activity_chart_dirty_log SELECT now64(9),toStartOfFiveMinutes(timestamp) AS window_start,sensor_id,campus_id FROM normalized_event_features FINAL WHERE timestamp>=parseDateTime64BestEffort(%s,6) AND timestamp<parseDateTime64BestEffort(%s,6) GROUP BY window_start,sensor_id,campus_id SETTINGS max_threads=1,max_block_size=2048,min_insert_block_size_rows=65536,min_insert_block_size_bytes=8388608,max_memory_usage=268435456,max_execution_time=20,async_insert=0`, chQuote(from.Format(time.RFC3339Nano)), chQuote(to.Format(time.RFC3339Nano)))
		if err = ch.exec(ctx, query); err != nil {
			tx.Rollback()
			return err
		}
		next := "running"
		if !to.Before(until) {
			next = "completed"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE application_read_model_backfills SET cursor_at=$1,status=$2,updated_at=now() WHERE name='activity-chart-buckets-v2'`, to, next); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
}
