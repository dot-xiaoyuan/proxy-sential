package store

import (
	"context"
	"database/sql"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"sort"
)

func eventIdentityScope(e normalized.Event) IdentityScope {
	return IdentityScope{Source: e.Source, SensorID: stringFromMap(e.Observer, "sensor_id"), CampusID: firstNonEmpty(stringFromMap(e.Subject, "campus_id"), stringFromMap(e.Payload, "campus_id")), AccessDomain: stringFromMap(e.Payload, "access_domain")}
}

// Durable sources have one authority writer. All other paths may derive device
// evidence, but must not rewrite their session facts or current counts.
func legacyAuthorityEvents(ctx context.Context, tx *sql.Tx, events []normalized.Event) ([]normalized.Event, error) {
	keys := []string{}
	seen := map[string]bool{}
	for _, e := range events {
		key := IdentityScopeKey(eventIdentityScope(e))
		if !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT scope_key FROM identity_pipeline_scopes WHERE enabled AND scope_key=ANY($1::text[])`, keys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	enabled := map[string]bool{}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			return nil, err
		}
		enabled[key] = true
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out := make([]normalized.Event, 0, len(events))
	for _, e := range events {
		if !enabled[IdentityScopeKey(eventIdentityScope(e))] {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *PostgresStore) writeLegacyIdentityEvents(ctx context.Context, events []normalized.Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	scopes := map[string]IdentityScope{}
	keys := []string{}
	for _, event := range events {
		scope := eventIdentityScope(event)
		key := IdentityScopeKey(scope)
		if _, ok := scopes[key]; !ok {
			scopes[key] = scope
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		scope := scopes[key]
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_pipeline_scopes(scope_key,source,sensor_id,campus_id,access_domain) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, key, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain); err != nil {
			return err
		}
		var enabled bool
		if err = tx.QueryRowContext(ctx, `SELECT enabled FROM identity_pipeline_scopes WHERE scope_key=$1 FOR SHARE`, key).Scan(&enabled); err != nil {
			return err
		}
		if enabled {
			return fmt.Errorf("identity source requires durable event-batches protocol")
		}
	}
	if _, err = writeIdentityEventsTx(ctx, tx, events); err != nil {
		return err
	}
	return tx.Commit()
}
