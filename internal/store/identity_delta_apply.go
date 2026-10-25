package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

func deltaScopeArgs(r identityDeltaRun) []any {
	return []any{r.Source, r.SensorID, r.CampusID, r.AccessDomain}
}

func (s *PostgresStore) diffIdentityDelta(ctx context.Context, r identityDeltaRun) error {
	tx, err := deltaBegin(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = deltaOwn(ctx, tx, r); err != nil {
		return err
	}
	keys := []string{}
	if !r.ExitsComplete {
		parts := strings.SplitN(r.ExitCursor, "\x1f", 2)
		if len(parts) < 2 {
			parts = []string{"", ""}
		}
		args := append(deltaScopeArgs(r), parts[0], parts[1], r.Batch)
		rows, e := tx.QueryContext(ctx, `SELECT session_id,ip FROM account_identity_session_projection WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND COALESCE(document->>'ended_at','')='' AND (session_id,ip)>($5,$6) ORDER BY session_id,ip LIMIT $7`, args...)
		if e != nil {
			return e
		}
		for rows.Next() {
			var session, ip string
			if err = rows.Scan(&session, &ip); err != nil {
				break
			}
			keys = append(keys, session+"\x1f"+ip)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			args = append(deltaScopeArgs(r), r.ID, keys, r.ObservedAt)
			_, err = tx.ExecContext(ctx, `INSERT INTO identity_delta_changes(run_id,member_key,ip,session_id,kind,document)
 SELECT $5,p.session_id||chr(31)||p.ip,p.ip,p.session_id,'end',p.document FROM unnest($6::text[]) k(member_key) JOIN account_identity_session_projection p ON p.session_id=split_part(k.member_key,chr(31),1) AND p.ip=split_part(k.member_key,chr(31),2)
 WHERE p.source=$1 AND p.sensor_id=$2 AND p.campus_id=$3 AND p.access_domain=$4
 AND p.confirmed_at<=$7 AND COALESCE(p.document->>'ended_at','')=''
 AND NOT EXISTS(SELECT 1 FROM identity_delta_members m WHERE m.run_id=$5 AND m.member_key=p.session_id||chr(31)||p.ip)
 ON CONFLICT DO NOTHING`, args...)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE identity_delta_runs SET state='diffing',exit_cursor=$2 WHERE run_id=$1`, r.ID, keys[len(keys)-1])
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE identity_delta_runs SET state='diffing',exits_complete=true WHERE run_id=$1`, r.ID)
		}
	} else {
		rows, e := tx.QueryContext(ctx, `SELECT member_key FROM identity_delta_members WHERE run_id=$1 AND member_key>$2 ORDER BY member_key LIMIT $3`, r.ID, r.DiffCursor, r.Batch)
		if e != nil {
			return e
		}
		for rows.Next() {
			var key string
			if err = rows.Scan(&key); err != nil {
				break
			}
			keys = append(keys, key)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			args := append(deltaScopeArgs(r), r.ID, keys, r.ObservedAt)
			_, err = tx.ExecContext(ctx, `INSERT INTO identity_delta_changes(run_id,member_key,ip,session_id,kind,document)
 SELECT m.run_id,m.member_key,m.ip,m.session_id,'upsert',m.document FROM identity_delta_members m
 LEFT JOIN account_identity_session_projection p ON p.source=$1 AND p.sensor_id=$2 AND p.campus_id=$3 AND p.access_domain=$4 AND p.session_id=m.session_id AND p.ip=m.ip
 WHERE m.run_id=$5 AND m.member_key=ANY($6::text[]) AND (p.session_id IS NULL OR (p.confirmed_at<=$7 AND (p.account_id IS DISTINCT FROM m.account_id OR (p.document`+projectionVolatileKeys+`) IS DISTINCT FROM (m.document`+projectionVolatileKeys+`))))
 ON CONFLICT DO NOTHING`, args...)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE identity_delta_runs SET diff_cursor=$2 WHERE run_id=$1`, r.ID, keys[len(keys)-1])
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE identity_delta_runs SET state='ready',changed_members=(SELECT count(*) FROM identity_delta_changes WHERE run_id=$1) WHERE run_id=$1`, r.ID)
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) applyIdentityDelta(ctx context.Context, r identityDeltaRun) error {
	if r.Mode != "delta" {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT member_key,session_id,ip,document,kind FROM identity_delta_changes WHERE run_id=$1 AND applied_at IS NULL ORDER BY ip,member_key LIMIT 501`, r.ID)
	if err != nil {
		return err
	}
	var members []identityDeltaMember
	for rows.Next() {
		var m identityDeltaMember
		if err = rows.Scan(&m.Key, &m.SessionID, &m.IP, &m.Document, &m.Kind); err != nil {
			break
		}
		members = append(members, m)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	batch, err := identityDeltaBatch(members, r.Batch, identityDeltaMaxBytes)
	if err != nil {
		return err
	}
	tx, err := deltaBegin(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = deltaOwn(ctx, tx, r); err != nil {
		return err
	}
	// Check the mode under the same row lock used by operator transitions.
	var mode string
	if err = tx.QueryRowContext(ctx, `SELECT mode FROM identity_delta_settings WHERE scope_key=$1 FOR SHARE`, r.ScopeKey).Scan(&mode); err != nil {
		return err
	}
	if mode != "delta" {
		return nil
	}
	var capture sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT capture_started_at FROM identity_delta_runs WHERE run_id=$1`, r.ID).Scan(&capture); err != nil {
		return err
	}
	if !capture.Valid && r.Source == "ncu-srun4k" {
		capture = sql.NullTime{Time: r.ObservedAt.Add(-time.Minute), Valid: true}
		if _, err = tx.ExecContext(ctx, `UPDATE identity_delta_runs SET capture_started_at=$2,capture_origin='bounded_legacy_reader' WHERE run_id=$1`, r.ID, capture.Time); err != nil {
			return err
		}
	}
	if !capture.Valid {
		return fmt.Errorf("capture interval missing; keep scope in legacy until a complete compatible snapshot arrives")
	}
	var newer bool
	orderArgs := append(deltaScopeArgs(r), r.ObservedAt)
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account_identity_projection_sources WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND observed_at>$5)`, orderArgs...).Scan(&newer); err != nil {
		return err
	}
	if newer {
		return errIdentityDeltaStaleSnapshot
	}
	if len(batch) == 0 {
		return finishIdentityDelta(ctx, tx, r)
	}
	var upserts, ends []identityDeltaMember
	ips := []string{}
	keys := []string{}
	for _, m := range batch {
		keys = append(keys, m.Key)
		if len(ips) == 0 || ips[len(ips)-1] != m.IP {
			ips = append(ips, m.IP)
		}
		if m.Kind == "end" {
			ends = append(ends, m)
		} else {
			upserts = append(upserts, m)
		}
	}
	// Keep old closed/account-replaced intervals before mutating the head row.
	raw, _ := json.Marshal(batch)
	args := append(deltaScopeArgs(r), raw, r.ScopeKey, r.ObservedAt)
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_projection_intervals(scope_key,session_id,ip,interval_hash,confirmed_at,document)
 SELECT $6,p.session_id,p.ip,md5(p.document::text),CASE WHEN COALESCE(p.document->>'ended_at','')='' THEN $7 ELSE p.confirmed_at END,
 CASE WHEN COALESCE(p.document->>'ended_at','')='' THEN jsonb_set(p.document,'{ended_at}',to_jsonb($7::timestamptz)) ELSE p.document END
 FROM jsonb_to_recordset($5::jsonb) m(session_id text,ip text,kind text,document jsonb)
 JOIN account_identity_session_projection p ON p.source=$1 AND p.sensor_id=$2 AND p.campus_id=$3 AND p.access_domain=$4 AND p.session_id=m.session_id AND p.ip=m.ip
 WHERE m.kind='upsert' AND p.confirmed_at<=$7 AND (COALESCE(p.document->>'ended_at','')<>'' OR p.account_id IS DISTINCT FROM m.document->>'account_id')
 ON CONFLICT DO NOTHING`, args...)
	if err != nil {
		return err
	}
	var written int64
	if len(upserts) > 0 {
		sessions, addresses, accounts, documents := []string{}, []string{}, []string{}, []string{}
		for _, m := range upserts {
			var v AccountSession
			if err = json.Unmarshal(m.Document, &v); err != nil {
				return err
			}
			sessions = append(sessions, m.SessionID)
			addresses = append(addresses, m.IP)
			accounts = append(accounts, v.AccountID)
			documents = append(documents, string(m.Document))
		}
		args = append(deltaScopeArgs(r), r.ObservedAt, sessions, addresses, accounts, documents)
		result, e := tx.ExecContext(ctx, deltaProjectionUpsertSQL(), args...)
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		written += n
	}
	if len(ends) > 0 {
		data, _ := json.Marshal(ends)
		args = append(deltaScopeArgs(r), data, r.ObservedAt)
		result, e := tx.ExecContext(ctx, `UPDATE account_identity_session_projection p SET document=jsonb_set(jsonb_set(p.document,'{ended_at}',to_jsonb($6::timestamptz)),'{session_status}','"stop"'),confirmed_at=$6
 FROM jsonb_to_recordset($5::jsonb) m(session_id text,ip text)
 WHERE p.source=$1 AND p.sensor_id=$2 AND p.campus_id=$3 AND p.access_domain=$4 AND p.session_id=m.session_id AND p.ip=m.ip AND p.confirmed_at<=$6 AND COALESCE(p.document->>'ended_at','')=''`, args...)
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		written += n
	}
	// Persistent notification, no device queue locks in this transaction.
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_delta_notifications(run_id,ip,document)
 SELECT $1,m.ip,jsonb_agg(m.document ORDER BY m.session_id) FROM jsonb_to_recordset($2::jsonb) m(ip text,session_id text,document jsonb) GROUP BY m.ip
 ON CONFLICT(run_id,ip) DO NOTHING`, r.ID, raw)
	if err != nil {
		return err
	}
	args = append(deltaScopeArgs(r), ips)
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_observation_wakes(kind,producer_mode,source,sensor_id,campus_id,access_domain,ip)
 SELECT 'snapshot_ip',mode,$1,$2,$3,$4,a.ip::inet FROM shared_observation_wake_mode CROSS JOIN unnest($5::text[]) a(ip) WHERE singleton AND mode IN ('shadow','async') AND EXISTS(
 SELECT 1 FROM shared_observation_jobs j JOIN shared_observation_mappings m ON m.active AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
 WHERE j.ip=a.ip::inet AND NOT j.expired AND j.canceled_epoch=''
 AND j.generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
 AND j.last_event_at>=now()-interval '1 hour'
 AND m.identity_source=$1 AND m.identity_sensor_id=$2 AND m.identity_campus_id=$3 AND m.identity_access_domain=$4 AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at)`, args...)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_delta_changes SET applied_at=clock_timestamp() WHERE run_id=$1 AND member_key=ANY($2::text[])`, r.ID, keys)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_delta_runs SET state='applying',applied_members=applied_members+$2,actual_writes=actual_writes+$3 WHERE run_id=$1`, r.ID, len(batch), written)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func finishIdentityDelta(ctx context.Context, tx *sql.Tx, r identityDeltaRun) error {
	var changed, applied, written, expected int64
	var started time.Time
	if err := tx.QueryRowContext(ctx, `SELECT changed_members,applied_members,actual_writes,expected_members,started_at FROM identity_delta_runs WHERE run_id=$1`, r.ID).Scan(&changed, &applied, &written, &expected, &started); err != nil {
		return err
	}
	if changed != applied {
		return fmt.Errorf("cannot complete calibration with unapplied differences")
	}
	var accounts, sessions int
	if err := tx.QueryRowContext(ctx, `SELECT count(DISTINCT account_id),count(DISTINCT session_id) FROM identity_delta_members WHERE run_id=$1`, r.ID).Scan(&accounts, &sessions); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, strings.Replace(snapshotPublishSQL, "snapshot_at<$2", "snapshot_at<=$2", 1), r.ScopeKey, r.ObservedAt, r.SnapshotID, accounts, sessions); err != nil {
		return err
	}
	args := append(deltaScopeArgs(r), r.ObservedAt)
	if _, err := tx.ExecContext(ctx, `INSERT INTO account_identity_projection_sources VALUES($1,$2,$3,$4,$5) ON CONFLICT(source,sensor_id,campus_id,access_domain) DO UPDATE SET observed_at=greatest(account_identity_projection_sources.observed_at,EXCLUDED.observed_at)`, args...); err != nil {
		return err
	}
	args = append(deltaScopeArgs(r), r.SnapshotID)
	if _, err := tx.ExecContext(ctx, snapshotLogProjectedSQL, args...); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM identity_snapshot_projection_jobs WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, args...); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE identity_delta_runs SET state='completed',completed_at=clock_timestamp() WHERE run_id=$1`, r.ID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Printf("identity_delta_completed run_id=%d members=%d differences=%d writes=%d elapsed_ms=%d", r.ID, expected, changed, written, time.Since(started).Milliseconds())
	return nil
}

func (s *PostgresStore) consumeIdentityDeltaNotification(ctx context.Context) (bool, error) {
	tx, err := deltaBegin(ctx, s.db)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT n.notification_id,n.document,r.observed_at FROM identity_delta_notifications n JOIN identity_delta_runs r USING(run_id)
 WHERE n.processed_at IS NULL AND n.run_id=(SELECT run_id FROM identity_delta_notifications WHERE processed_at IS NULL ORDER BY notification_id LIMIT 1)
 ORDER BY n.notification_id LIMIT 100 FOR UPDATE OF n SKIP LOCKED`)
	if err != nil {
		return false, err
	}
	ids := []int64{}
	sessions := []AccountSession{}
	var at time.Time
	bytes := 0
	for rows.Next() {
		var id int64
		var raw []byte
		if err = rows.Scan(&id, &raw, &at); err != nil {
			break
		}
		var group []AccountSession
		if err = json.Unmarshal(raw, &group); err != nil {
			break
		}
		if len(group) > identityDeltaMaxMembers || len(raw) > identityDeltaMaxBytes {
			err = fmt.Errorf("notification exceeds IP member bound")
			break
		}
		if len(ids) > 0 && (len(sessions)+len(group) > identityDeltaMaxMembers || bytes+len(raw) > identityDeltaMaxBytes) {
			break
		}
		ids = append(ids, id)
		sessions = append(sessions, group...)
		bytes += len(raw)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return false, err
	}
	if len(ids) == 0 {
		return false, nil
	}
	if err = enqueueSharedDeviceProfileJobs(ctx, tx, sessions, at); err != nil {
		return true, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_delta_notifications SET processed_at=clock_timestamp() WHERE notification_id=ANY($1::bigint[])`, ids); err != nil {
		return true, err
	}
	return true, tx.Commit()
}

// A replacement starts a new presence interval. The legacy upsert's min-start
// rule applies only while the same account remains present.
func deltaProjectionUpsertSQL() string {
	q := strings.Replace(projectionUpsertSQL, "CASE WHEN (account_identity_session_projection.document->>'started_at')", "CASE WHEN account_identity_session_projection.account_id IS DISTINCT FROM EXCLUDED.account_id OR COALESCE(account_identity_session_projection.document->>'ended_at','')<>'' THEN EXCLUDED.document->'started_at' WHEN (account_identity_session_projection.document->>'started_at')", 1)
	return strings.Replace(q, "CASE WHEN COALESCE(account_identity_session_projection.document->>'ended_at','')<>'' THEN", "CASE WHEN account_identity_session_projection.account_id IS DISTINCT FROM EXCLUDED.account_id OR COALESCE(account_identity_session_projection.document->>'ended_at','')<>'' THEN", 1)
}
