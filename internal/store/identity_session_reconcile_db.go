package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"proxy-sentinel/internal/policy"
)

// reconcileChunk bounds one array argument. Statements stay small and planner-friendly.
const reconcileChunk = 500

// identityQueryer is satisfied by *sql.DB and *sql.Tx, so the same code runs in tests and in the commit transaction.
type identityQueryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Held counts an empty snapshot that was not applied because stored sessions are still open.
type sessionReconcileStats struct {
	Inserted, Confirmed, Ended, Conflicts, Held int
}

// storedSession is one account_sessions row as the reconciler needs it.
type storedSession struct {
	SessionID, AccountID, EndpointID, IP, MAC, Source, SensorID, CampusID, AccessDomain, LoginKey string
	StartedAt                                                                                     time.Time
	EndedAt                                                                                       sql.NullTime
	LastConfirmedAt                                                                               string
}

// sessionSelectSQL reads access_domain and last_confirmed_at from policy_metadata: the table has no column for them.
const sessionSelectSQL = `SELECT session_id, COALESCE(account_id,''), COALESCE(endpoint_id,''), COALESCE(host(ip),''), COALESCE(mac,''), source, started_at, ended_at, login_key, sensor_id, COALESCE(campus_id,''), COALESCE(policy_metadata->>'access_domain',''), COALESCE(policy_metadata->>'last_confirmed_at','') FROM account_sessions`

func sessionRowColumns() []string {
	return []string{"session_id", "account_id", "endpoint_id", "ip", "mac", "source", "started_at", "ended_at", "login_key", "sensor_id", "campus_id", "access_domain", "last_confirmed_at"}
}

func sessionFromStoredRow(s storedSession) policy.Session {
	row := policy.Session{
		ID: s.SessionID, LoginKey: s.LoginKey, AccountID: s.AccountID, EndpointID: s.EndpointID, IP: s.IP, MAC: s.MAC,
		Source: s.Source, SensorID: s.SensorID, CampusID: s.CampusID, AccessDomain: s.AccessDomain, StartedAt: s.StartedAt,
	}
	if s.EndedAt.Valid {
		row.EndedAt = s.EndedAt.Time
	}
	if confirmed, err := time.Parse(time.RFC3339Nano, s.LastConfirmedAt); err == nil {
		row.ConfirmedAt = confirmed
	}
	return row
}

// accountSessionFromReconcile builds the row written for a member that had none. Provenance keeps
// the snapshot and scope, so the origin of a reconciled row is visible without the snapshot table.
// Identity confidence stays zero: a snapshot member carries no per-record confidence.
func accountSessionFromReconcile(row policy.Session, snapshot IdentitySnapshot) AccountSession {
	return AccountSession{
		SessionID: row.ID, LoginKey: row.LoginKey, SensorID: row.SensorID, AccountID: row.AccountID, EndpointID: row.EndpointID,
		IP: row.IP, MAC: row.MAC, Source: row.Source, StartedAt: row.StartedAt.UTC().Format(time.RFC3339Nano),
		LastConfirmedAt: row.ConfirmedAt.UTC().Format(time.RFC3339Nano), HeartbeatSeconds: row.HeartbeatSeconds,
		ReconcileSeconds: row.ReconcileSeconds, GroupID: row.GroupID, ProductID: row.ProductID, DeviceClass: row.DeviceClass,
		CampusID: row.CampusID, AccessDomain: row.AccessDomain, SessionStatus: "reconcile",
		RawRef: map[string]any{"source": snapshot.Source, "sensor_id": snapshot.SensorID, "campus_id": snapshot.CampusID, "access_domain": snapshot.AccessDomain, "snapshot_id": snapshot.SnapshotID},
	}
}

// loadSnapshotSessionRows reads what the planner needs and nothing more: every open row of the
// snapshot's source, plus rows matched by member session ID or login key. It never reads history.
func loadSnapshotSessionRows(ctx context.Context, q identityQueryer, snapshot IdentitySnapshot) ([]policy.Session, error) {
	rows := map[string]policy.Session{}
	add := func(query string, args ...any) error {
		result, err := q.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer result.Close()
		for result.Next() {
			var s storedSession
			var ip, mac, endpoint, account, campus, domain, confirmed sql.NullString
			if err := result.Scan(&s.SessionID, &account, &endpoint, &ip, &mac, &s.Source, &s.StartedAt, &s.EndedAt, &s.LoginKey, &s.SensorID, &campus, &domain, &confirmed); err != nil {
				return err
			}
			s.AccountID, s.EndpointID, s.IP, s.MAC = account.String, endpoint.String, ip.String, mac.String
			s.CampusID, s.AccessDomain, s.LastConfirmedAt = campus.String, domain.String, confirmed.String
			if _, seen := rows[s.SessionID]; !seen {
				rows[s.SessionID] = sessionFromStoredRow(s)
			}
		}
		return result.Err()
	}
	if err := add(sessionSelectSQL+` WHERE ended_at IS NULL AND source = $1`, snapshot.Source); err != nil {
		return nil, err
	}
	ids, keys := []string{}, []string{}
	seenKey := map[string]bool{}
	for _, member := range snapshot.Sessions {
		ids = append(ids, member.ID)
		if member.LoginKey != "" && !seenKey[member.LoginKey] {
			seenKey[member.LoginKey] = true
			keys = append(keys, member.LoginKey)
		}
	}
	for start := 0; start < len(ids); start += reconcileChunk {
		if err := add(sessionSelectSQL+` WHERE session_id = ANY($1::text[])`, textArray(ids[start:min(start+reconcileChunk, len(ids))])); err != nil {
			return nil, err
		}
	}
	for start := 0; start < len(keys); start += reconcileChunk {
		if err := add(sessionSelectSQL+` WHERE login_key <> '' AND login_key = ANY($1::text[])`, textArray(keys[start:min(start+reconcileChunk, len(keys))])); err != nil {
			return nil, err
		}
	}
	out := make([]policy.Session, 0, len(rows))
	for _, row := range rows {
		out = append(out, row)
	}
	return out, nil
}

// applySessionReconcileActions writes the planned changes. Inserts reuse the session upsert, so a
// row that appeared concurrently merges instead of failing. Confirm and end are batched and guarded
// so a replay or a newer event never moves a row backwards.
func applySessionReconcileActions(ctx context.Context, q identityQueryer, snapshot IdentitySnapshot, actions []sessionReconcileAction) (sessionReconcileStats, error) {
	stats := sessionReconcileStats{}
	var inserts []AccountSession
	var confirmIDs, confirmAt, endIDs, endAt []string
	for _, action := range actions {
		switch action.Kind {
		case sessionReconcileInsert:
			inserts = append(inserts, accountSessionFromReconcile(action.Row, snapshot))
		case sessionReconcileConfirm:
			confirmIDs = append(confirmIDs, action.SessionID)
			confirmAt = append(confirmAt, action.At.UTC().Format(time.RFC3339Nano))
		case sessionReconcileEnd:
			endIDs = append(endIDs, action.SessionID)
			endAt = append(endAt, action.At.UTC().Format(time.RFC3339Nano))
		default:
			return stats, fmt.Errorf("unknown session reconcile action %q", action.Kind)
		}
	}
	for start := 0; start < len(inserts); start += reconcileChunk {
		chunk := inserts[start:min(start+reconcileChunk, len(inserts))]
		if err := upsertAccountSessionsBatch(ctx, q, chunk); err != nil {
			return stats, err
		}
		stats.Inserted += len(chunk)
	}
	for start := 0; start < len(confirmIDs); start += reconcileChunk {
		end := min(start+reconcileChunk, len(confirmIDs))
		if _, err := q.ExecContext(ctx, `UPDATE account_sessions AS s SET policy_metadata = jsonb_set(COALESCE(s.policy_metadata,'{}'::jsonb), '{last_confirmed_at}', to_jsonb(v.at::text)), updated_at = now()
FROM unnest($1::text[], $2::text[]) AS v(session_id, at)
WHERE s.session_id = v.session_id AND s.ended_at IS NULL
  AND COALESCE(NULLIF(s.policy_metadata->>'last_confirmed_at',''),'-infinity')::timestamptz < v.at::timestamptz`,
			textArray(confirmIDs[start:end]), textArray(confirmAt[start:end])); err != nil {
			return stats, err
		}
		stats.Confirmed += end - start
	}
	for start := 0; start < len(endIDs); start += reconcileChunk {
		end := min(start+reconcileChunk, len(endIDs))
		if _, err := q.ExecContext(ctx, `UPDATE account_sessions AS s SET ended_at = v.at::timestamptz, session_status = 'stop', policy_metadata = jsonb_set(COALESCE(s.policy_metadata,'{}'::jsonb), '{last_confirmed_at}', to_jsonb(v.at::text)), updated_at = now()
FROM unnest($1::text[], $2::text[]) AS v(session_id, at)
WHERE s.session_id = v.session_id AND s.ended_at IS NULL`,
			textArray(endIDs[start:end]), textArray(endAt[start:end])); err != nil {
			return stats, err
		}
		stats.Ended += end - start
	}
	return stats, nil
}

// lastAppliedSnapshotAt returns the newest snapshot already committed for the scope.
func lastAppliedSnapshotAt(ctx context.Context, q identityQueryer, scope IdentityScope) (time.Time, error) {
	var at sql.NullTime
	err := q.QueryRowContext(ctx, `SELECT max(observed_at) FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4`, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain).Scan(&at)
	if err != nil {
		return time.Time{}, err
	}
	return at.Time, nil
}

// reconcileSnapshotSessionsTx runs inside the snapshot commit transaction, under the scope lock.
func reconcileSnapshotSessionsTx(ctx context.Context, tx *sql.Tx, snapshot IdentitySnapshot) (sessionReconcileStats, error) {
	lastApplied, err := lastAppliedSnapshotAt(ctx, tx, snapshot.IdentityScope)
	if err != nil {
		return sessionReconcileStats{}, err
	}
	rows, err := loadSnapshotSessionRows(ctx, tx, snapshot)
	if err != nil {
		return sessionReconcileStats{}, err
	}
	actions, conflicts := planSnapshotSessionReconcile(snapshot, rows, lastApplied)
	stats, err := applySessionReconcileActions(ctx, tx, snapshot, actions)
	stats.Conflicts = conflicts
	if len(snapshot.Sessions) == 0 && len(rows) > 0 {
		stats.Held = 1
	}
	return stats, err
}

// textArray passes a Go slice as a text[] argument; the pgx driver encodes it directly.
func textArray(values []string) any { return values }
