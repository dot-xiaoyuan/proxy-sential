package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"strconv"
	"strings"
	"time"
)

// errIdentityWriteBusy reports that another writer holds the identity write lock. The
// caller must leave its queued work in place: the batch was never started, not applied.
var errIdentityWriteBusy = errors.New("identity write in progress")

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
		if errors.Is(err, errIdentityWriteBusy) {
			// Roll back without deleting the job: an identity writer owns the projection
			// trigger rows right now, so this snapshot is retried on a later cycle rather
			// than holding a job row lock while queueing behind that writer.
			tx.Rollback()
			return nil
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
	// account_identity_session_projection carries inventory_projection_change, a FOR EACH
	// ROW trigger that upserts endpoint_inventory_projection_jobs once per session. This
	// batch enqueues those rows in snapshot order, while the identity write path
	// (writeIdentityEventsTx, which holds the identity write lock) enqueues the same rows
	// ordered by endpoint_id. Interleaving the two takes the job row locks in opposite
	// order, and the field measured the result as `deadlock detected (SQLSTATE 40P01)` on
	// this batch for three hours straight: every projection rolled back, so device state
	// stopped advancing while no error ever surfaced in the pages. Joining the identity
	// write lock orders the two writers instead of interleaving them; this transaction
	// never blocks on it because a busy writer is reported as errIdentityWriteBusy.
	if locked, err := tryIdentityWriteLock(ctx, tx); err != nil {
		return err
	} else if !locked {
		return errIdentityWriteBusy
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
	// Only snapshots that reached the projection count as confirmations (see identity_snapshot_log).
	if _, err = tx.ExecContext(ctx, snapshotLogProjectedSQL, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.SnapshotID); err != nil {
		return err
	}
	// Complete snapshots are authoritative membership projections, not a second
	// copy of the realtime accounting/device-fact stream. Keeping them in the
	// dedicated table avoids duplicate device evidence and lock contention with
	// live event materialization while preserving account and router bindings.
	keys := make([]string, 0, len(snapshot.Events))
	projectedSessions := make([]AccountSession, 0, len(snapshot.Events))
	sessionIDs := make([]string, 0, 2000)
	ips := make([]string, 0, 2000)
	accountIDs := make([]string, 0, 2000)
	documents := make([]string, 0, 2000)
	flush := func() error {
		if len(sessionIDs) == 0 {
			return nil
		}
		_, execErr := tx.ExecContext(ctx, projectionUpsertSQL, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.ObservedAt, sessionIDs, ips, accountIDs, documents)
		sessionIDs = sessionIDs[:0]
		ips = ips[:0]
		accountIDs = accountIDs[:0]
		documents = documents[:0]
		return execErr
	}
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
		projectedSessions = append(projectedSessions, session)
		keys = append(keys, session.SessionID+"\x1f"+session.IP)
		sessionIDs = append(sessionIDs, session.SessionID)
		ips = append(ips, session.IP)
		accountIDs = append(accountIDs, session.AccountID)
		documents = append(documents, string(raw))
		if len(sessionIDs) == cap(sessionIDs) {
			if err = flush(); err != nil {
				return err
			}
		}
	}
	if err = flush(); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE account_identity_session_projection SET document=jsonb_set(jsonb_set(document,'{ended_at}',to_jsonb($7::text)), '{session_status}','"stop"'::jsonb),confirmed_at=$5::timestamptz WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND confirmed_at<=$5::timestamptz AND COALESCE(document->>'ended_at','')='' AND NOT(session_id||chr(31)||ip=ANY($6::text[]))`, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.ObservedAt, keys, snapshot.ObservedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	return enqueueSharedDeviceProfileJobs(ctx, tx, projectedSessions, snapshot.ObservedAt)
}

func (s *PostgresStore) projectedAccountSessions(ctx context.Context, account string, limit int) ([]AccountSession, error) {
	rows, err := s.db.QueryContext(ctx, projectedAccountSessionsSQL, account, limit)
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

// projectionVolatileKeys are document fields that change with every snapshot without changing the
// membership: the snapshot time, its provenance, the earliest start and the first confirmation, the
// last two merged separately.
const projectionVolatileKeys = ` - 'last_confirmed_at' - 'raw_ref' - 'started_at' - 'first_confirmed_at'`

// projectionUpsertSQL writes only members that are new or whose account or content changed. An
// unchanged member stays as it is: its confirmation comes from the scope's latest projected snapshot
// (projectionConfirmedSQL), so rewriting it only rewrote every confirmed_at index and fired the
// shared-profile trigger for the whole inventory on every snapshot.
const projectionUpsertSQL = `INSERT INTO account_identity_session_projection(source,sensor_id,campus_id,access_domain,session_id,ip,account_id,confirmed_at,document)
SELECT $1,$2,$3,$4,rows.session_id,rows.ip,rows.account_id,$5::timestamptz,rows.document::jsonb||jsonb_build_object('first_confirmed_at',$5::timestamptz)
FROM unnest($6::text[],$7::text[],$8::text[],$9::text[]) AS rows(session_id,ip,account_id,document)
ON CONFLICT(source,sensor_id,campus_id,access_domain,session_id,ip) DO UPDATE SET account_id=EXCLUDED.account_id,confirmed_at=EXCLUDED.confirmed_at,document=jsonb_set(jsonb_set(EXCLUDED.document,'{started_at}',CASE WHEN (account_identity_session_projection.document->>'started_at')::timestamptz <= (EXCLUDED.document->>'started_at')::timestamptz THEN account_identity_session_projection.document->'started_at' ELSE EXCLUDED.document->'started_at' END),'{first_confirmed_at}',CASE WHEN COALESCE(account_identity_session_projection.document->>'ended_at','')<>'' THEN EXCLUDED.document->'first_confirmed_at' ELSE COALESCE(account_identity_session_projection.document->'first_confirmed_at',to_jsonb(account_identity_session_projection.confirmed_at)) END) WHERE account_identity_session_projection.confirmed_at<=EXCLUDED.confirmed_at AND (account_identity_session_projection.account_id IS DISTINCT FROM EXCLUDED.account_id OR (account_identity_session_projection.document` + projectionVolatileKeys + `) IS DISTINCT FROM (EXCLUDED.document` + projectionVolatileKeys + `))`

// projectionConfirmedSQL is a projection row's effective confirmation. An open member is confirmed by
// the latest projected snapshot of its scope; the per-row rewrite used to store exactly that value.
const projectionConfirmedSQL = "CASE WHEN COALESCE(p.document->>'ended_at','')='' THEN GREATEST(p.confirmed_at,COALESCE(src.observed_at,p.confirmed_at)) ELSE p.confirmed_at END"

// projectedAccountSessionsSQL lists an account's projected sessions, newest effective confirmation first.
const projectedAccountSessionsSQL = `SELECT p.document FROM account_identity_session_projection p LEFT JOIN account_identity_projection_sources src USING(source,sensor_id,campus_id,access_domain) WHERE p.account_id=$1 ORDER BY ` + projectionConfirmedSQL + ` DESC,p.source,p.session_id,p.ip LIMIT $2`
