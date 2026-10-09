package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"strconv"
	"strings"
	"time"
)

// Projection is display-only. Policy reconciliation continues to use immutable
// authority facts and complete snapshots, including their coverage boundaries.
func accountSessionScopeKey(session AccountSession) string {
	raw, _ := json.Marshal([]string{session.Source, session.CampusID, session.AccessDomain, stringFromMap(session.RawRef, "sensor_id"), session.SessionID, session.IP})
	return string(raw)
}

func (s *PostgresStore) projectPendingIdentitySnapshots(ctx context.Context, limit int) error {
	for i := 0; i < limit; i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var raw []byte
		err = tx.QueryRowContext(ctx, `SELECT f.document FROM identity_snapshot_projection_jobs j JOIN identity_full_snapshots f USING(source,sensor_id,campus_id,access_domain,snapshot_id) ORDER BY j.observed_at,j.source,j.snapshot_id FOR UPDATE OF j SKIP LOCKED LIMIT 1`).Scan(&raw)
		if err == sql.ErrNoRows {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		var snapshot IdentitySnapshot
		if err = json.Unmarshal(raw, &snapshot); err == nil {
			err = projectIdentitySnapshot(ctx, tx, snapshot)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM identity_snapshot_projection_jobs WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.SnapshotID)
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func projectIdentitySnapshot(ctx context.Context, tx *sql.Tx, snapshot IdentitySnapshot) error {
	scopeRaw, _ := json.Marshal(snapshot.IdentityScope)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7136))`, string(scopeRaw)); err != nil {
		return err
	}
	args := []any{snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.ObservedAt}
	var latest bool
	err := tx.QueryRowContext(ctx, `INSERT INTO account_identity_projection_sources VALUES($1,$2,$3,$4,$5) ON CONFLICT(source,sensor_id,campus_id,access_domain) DO UPDATE SET observed_at=EXCLUDED.observed_at WHERE account_identity_projection_sources.observed_at<=EXCLUDED.observed_at RETURNING true`, args...).Scan(&latest)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	state := BuildIdentityState(snapshot.Events)
	state.Sessions = nil // snapshot membership is a projection, not accounting facts
	if err = writeIdentityState(ctx, tx, state); err != nil {
		return err
	}
	if err = writeEndpointDeviceProfiles(ctx, tx, state); err != nil {
		return err
	}
	keys := []string{}
	for _, event := range snapshot.Events {
		state := BuildIdentityState([]normalized.Event{event})
		if len(state.Sessions) != 1 {
			return fmt.Errorf("snapshot event has no unique account session")
		}
		session := state.Sessions[0]
		if strings.HasPrefix(snapshot.Source, "srun4k:") || snapshot.Source == "ncu-srun4k" {
			generation := stringFromMap(event.Payload, "source_login_generation")
			if seconds, e := strconv.ParseInt(generation, 10, 64); e == nil && seconds > 0 && strconv.FormatInt(seconds, 10) == generation && !time.Unix(seconds, 0).After(snapshot.ObservedAt) {
				session.StartedAt = time.Unix(seconds, 0).UTC().Format(time.RFC3339Nano)
			}
		}
		raw, e := json.Marshal(session)
		if e != nil {
			return e
		}
		keys = append(keys, session.SessionID+"\x1f"+session.IP)
		_, err = tx.ExecContext(ctx, `INSERT INTO account_identity_session_projection VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(source,sensor_id,campus_id,access_domain,session_id,ip) DO UPDATE SET account_id=EXCLUDED.account_id,confirmed_at=EXCLUDED.confirmed_at,document=jsonb_set(EXCLUDED.document,'{started_at}',CASE WHEN (account_identity_session_projection.document->>'started_at')::timestamptz <= (EXCLUDED.document->>'started_at')::timestamptz THEN account_identity_session_projection.document->'started_at' ELSE EXCLUDED.document->'started_at' END) WHERE account_identity_session_projection.confirmed_at<=EXCLUDED.confirmed_at`, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, session.SessionID, session.IP, session.AccountID, snapshot.ObservedAt, raw)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE account_identity_session_projection SET document=jsonb_set(jsonb_set(document,'{ended_at}',to_jsonb($7::text)), '{session_status}','"stop"'::jsonb),confirmed_at=$5::timestamptz WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND confirmed_at<=$5::timestamptz AND COALESCE(document->>'ended_at','')='' AND NOT(session_id||chr(31)||ip=ANY($6::text[]))`, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.ObservedAt, keys, snapshot.ObservedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *PostgresStore) projectedAccountSessions(ctx context.Context, account string, limit int) ([]AccountSession, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT document FROM account_identity_session_projection WHERE account_id=$1 ORDER BY confirmed_at DESC,source,session_id,ip LIMIT $2`, account, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AccountSession{}
	for rows.Next() {
		var raw []byte
		var session AccountSession
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &session); err != nil {
			return nil, err
		}
		out = append(out, session)
	}
	return out, rows.Err()
}
