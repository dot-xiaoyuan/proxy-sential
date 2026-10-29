package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

// The authentication result owns session relationships and their validity.
// Device recognition owns fingerprints. Persist all supplied endpoint evidence
// here; the durable endpoint recognition trigger, not this transaction, updates
// the device's presentation. Generic device events retain their existing path.
func authenticationEventsOnly(events []normalized.Event) bool {
	if len(events) == 0 {
		return false
	}
	for _, event := range events {
		if event.Type != "identity" {
			return false
		}
	}
	return true
}

func (s *PostgresStore) commitAuthenticationEndpoints(ctx context.Context, events []normalized.Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = boundIdentityStatements(ctx, tx); err != nil {
		return err
	}
	state := BuildIdentityState(events)
	if err = upsertEndpointEntitiesBatch(ctx, tx, state.Endpoints); err != nil {
		return err
	}
	if err = upsertInfrastructureEntitiesBatch(ctx, tx, state.Infrastructure); err != nil {
		return err
	}
	return tx.Commit()
}

// Lock only the supplied business keys, in order, before merging. RETURNING
// excludes identical/older no-ops. Both ends of a changed relationship must be
// invalidated: moving a session away from a device also changes its old profile.
// Joining previous in the INSERT establishes its evaluation dependency; no
// historical or whole-source session scan is involved.
var changedAuthenticationSessionsSQL = func() string {
	statement := fragmentSessionUpsertSQL
	replace := func(old, next string) {
		if strings.Count(statement, old) != 1 {
			panic("authentication result SQL assignment drift: " + old)
		}
		statement = strings.Replace(statement, old, next, 1)
	}
	replace("session_status, policy_metadata)", "session_status, policy_metadata, last_confirmed_at)")
	replace("t.metadata::jsonb\nFROM unnest", "t.metadata::jsonb, COALESCE(NULLIF(t.metadata::jsonb->>'last_confirmed_at','')::timestamptz,t.started_at)\nFROM unnest")
	replace("  updated_at =", "  last_confirmed_at = GREATEST(account_sessions.last_confirmed_at,EXCLUDED.last_confirmed_at),\n  updated_at =")
	statement += "\n OR account_sessions.last_confirmed_at IS NULL"
	const boundary = "\nON CONFLICT(session_id)"
	replace(boundary, "\nLEFT JOIN previous ON previous.session_id=t.session_id\nWHERE true"+boundary)
	return `WITH previous AS MATERIALIZED (
 SELECT session_id,COALESCE(endpoint_id,'') AS endpoint_id,COALESCE(mac,'') AS mac
 FROM account_sessions WHERE session_id=ANY($1::text[]) ORDER BY session_id FOR UPDATE
), applied AS (` + statement + `
 RETURNING session_id,COALESCE(endpoint_id,'') AS endpoint_id,COALESCE(mac,'') AS mac
), departures AS (
 INSERT INTO identity_endpoint_invalidations(endpoint_id)
 SELECT DISTINCT previous.endpoint_id FROM previous JOIN applied USING(session_id)
 JOIN endpoint_entities e ON e.endpoint_id=previous.endpoint_id
 WHERE previous.endpoint_id<>'' AND previous.endpoint_id IS DISTINCT FROM applied.endpoint_id
 ORDER BY previous.endpoint_id
 ON CONFLICT(endpoint_id) DO UPDATE SET revision=identity_endpoint_invalidations.revision+1,
 dirty_since=CASE WHEN identity_endpoint_invalidations.completed_revision=identity_endpoint_invalidations.revision THEN clock_timestamp() ELSE identity_endpoint_invalidations.dirty_since END
) SELECT session_id,endpoint_id,mac FROM applied
UNION SELECT previous.session_id,previous.endpoint_id,previous.mac FROM previous JOIN applied USING(session_id)`
}()

func upsertChangedAuthenticationSessions(ctx context.Context, tx *sql.Tx, sessions []AccountSession) ([]AccountSession, error) {
	args := accountSessionBatchArguments(sessions)
	if len(args) == 0 {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, changedAuthenticationSessionsSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var changed []AccountSession
	for rows.Next() {
		var item AccountSession
		if err = rows.Scan(&item.SessionID, &item.EndpointID, &item.MAC); err != nil {
			return nil, err
		}
		changed = append(changed, item)
	}
	return changed, rows.Err()
}

func writeAuthenticationSessionsTx(ctx context.Context, tx *sql.Tx, events []normalized.Event) error {
	if err := boundIdentityStatements(ctx, tx); err != nil {
		return err
	}
	changed, err := upsertChangedAuthenticationSessions(ctx, tx, fragmentCompatibilitySessions(events))
	if err != nil {
		return err
	}
	// This is a durable invalidation in the same transaction as the session
	// result. Expensive profile reconstruction remains outside authentication.
	var observed time.Time
	for _, event := range events {
		if at, ok := parseTime(event.Timestamp); ok && at.After(observed) {
			observed = at
		}
	}
	return enqueueSharedDeviceProfileJobs(ctx, tx, changed, observed)
}

// Results commit before revision acknowledgement. A crash replays safely and
// a newer departure cannot be accidentally acknowledged by this pass.
func (s *PostgresStore) refreshAuthenticationDepartures(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT endpoint_id,revision FROM identity_endpoint_invalidations WHERE completed_revision<revision ORDER BY dirty_since,endpoint_id LIMIT 64`)
	if err != nil {
		return 0, err
	}
	type departure struct {
		Endpoint string `json:"endpoint_id"`
		Revision int64  `json:"revision"`
	}
	var changed []departure
	var ids []string
	for rows.Next() {
		var item departure
		if err = rows.Scan(&item.Endpoint, &item.Revision); err != nil {
			rows.Close()
			return 0, err
		}
		changed, ids = append(changed, item), append(ids, item.Endpoint)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	if err = s.refreshEndpointStates(ctx, ids); err != nil {
		return 0, err
	}
	raw, err := json.Marshal(changed)
	if err != nil {
		return 0, err
	}
	_, err = s.db.ExecContext(ctx, completeAuthenticationDeparturesSQL, raw)
	return len(ids), err
}

const completeAuthenticationDeparturesSQL = `UPDATE identity_endpoint_invalidations i SET completed_revision=GREATEST(i.completed_revision,r.revision) FROM jsonb_to_recordset($1::jsonb) r(endpoint_id text,revision bigint) WHERE i.endpoint_id=r.endpoint_id AND i.completed_revision<r.revision AND i.revision>=r.revision`
