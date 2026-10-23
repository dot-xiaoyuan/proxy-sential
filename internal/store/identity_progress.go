package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

func identitySplitProgressEnabled() bool {
	return os.Getenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS") == "true"
}

// Only SELECT callers use this compatibility view. Lease locks and writes go
// directly to the owning progress table, never through the joined view.
func IdentityScopeStatusSQL(query string) string {
	if identitySplitProgressEnabled() {
		return strings.ReplaceAll(query, "identity_pipeline_scopes", "identity_pipeline_scope_status")
	}
	return query
}

func ensureIdentityProgress(ctx context.Context, tx *sql.Tx, key string) error {
	for _, query := range []string{
		`INSERT INTO identity_receive_progress SELECT scope_key,accepted_sequence,greatest(pending_records,export_pending_records),NULL,accepted_sequence FROM identity_pipeline_scopes WHERE scope_key=$1 ON CONFLICT DO NOTHING`,
		`INSERT INTO identity_consume_progress SELECT scope_key,processed_sequence,greatest(pending_records,export_pending_records)-pending_records,current_generation,lease_epoch,lease_until,oldest_pending_at,processed_at,heartbeat_at,last_error FROM identity_pipeline_scopes WHERE scope_key=$1 ON CONFLICT DO NOTHING`,
		`INSERT INTO identity_export_progress SELECT scope_key,greatest(pending_records,export_pending_records)-export_pending_records,export_last_error,export_heartbeat_at,export_completed_at FROM identity_pipeline_scopes WHERE scope_key=$1 ON CONFLICT DO NOTHING`,
	} {
		if _, err := tx.ExecContext(ctx, query, key); err != nil {
			return err
		}
	}
	return nil
}

const acceptIdentitySplitSQL = `UPDATE identity_receive_progress r SET accepted_sequence=r.accepted_sequence+1,total_records=r.total_records+$2,accepted_at=now()
 FROM identity_consume_progress c,identity_export_progress e WHERE r.scope_key=$1 AND c.scope_key=r.scope_key AND e.scope_key=r.scope_key
 AND r.total_records+$2-c.processed_records<=$3 AND r.total_records+$2-e.exported_records<=$3 RETURNING r.accepted_sequence`

const claimIdentitySplitSQL = `SELECT c.scope_key,c.current_generation,c.lease_epoch+1,c.processed_sequence+1,s.snapshot_at
 FROM identity_consume_progress c JOIN identity_receive_progress r USING(scope_key) JOIN identity_pipeline_scopes s USING(scope_key)
 WHERE s.sensor_id=$1 AND s.enabled AND r.total_records>c.processed_records AND (c.lease_until IS NULL OR c.lease_until<now())
 ORDER BY c.oldest_pending_at NULLS LAST,c.scope_key FOR UPDATE OF c SKIP LOCKED LIMIT 1`

const applyIdentitySplitSQL = `UPDATE identity_consume_progress SET processed_at=now(),processed_records=processed_records+$3,processed_sequence=$5-CASE WHEN $4 THEN 0 ELSE 1 END,lease_until=NULL,heartbeat_at=now(),last_error='',
 oldest_pending_at=(SELECT accepted_at FROM identity_ingest_batches WHERE protocol_version=2 AND scope_key=$1 AND sequence=CASE WHEN $4 THEN $5+1 ELSE $5 END)
 WHERE scope_key=$1 AND lease_epoch=$2 AND lease_until>clock_timestamp() AND current_generation=$6`

func recordIdentityPendingIPs(ctx context.Context, tx *sql.Tx, batch, key string, events []normalized.Event) error {
	type pending struct {
		IP    string    `json:"ip"`
		First time.Time `json:"first"`
		Last  time.Time `json:"last"`
	}
	grouped := map[string]pending{}
	for _, s := range policyRows(events) {
		v, ok := grouped[s.IP]
		if !ok {
			v = pending{s.IP, s.ConfirmedAt, s.ConfirmedAt}
		}
		if s.ConfirmedAt.Before(v.First) {
			v.First = s.ConfirmedAt
		}
		if s.ConfirmedAt.After(v.Last) {
			v.Last = s.ConfirmedAt
		}
		grouped[s.IP] = v
	}
	rows := make([]pending, 0, len(grouped))
	for _, p := range grouped {
		rows = append(rows, p)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_inbox_ip_pending(batch_id,scope_key,ip,first_event_at,last_event_at,accepted_at)
 SELECT $1,$2,r.ip,r.first,r.last,now() FROM jsonb_to_recordset($3::jsonb) r(ip text,first timestamptz,last timestamptz) ON CONFLICT DO NOTHING`, batch, key, raw)
	return err
}

func identityConsumeSQL(query string) string {
	if identitySplitProgressEnabled() {
		return strings.ReplaceAll(query, "identity_pipeline_scopes", "identity_consume_progress")
	}
	return query
}
func identityExportSQL(query string) string {
	if identitySplitProgressEnabled() {
		return strings.ReplaceAll(query, "identity_pipeline_scopes", "identity_export_progress")
	}
	return query
}
