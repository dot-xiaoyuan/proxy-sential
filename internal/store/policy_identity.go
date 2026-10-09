package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"sort"
	"strings"
	"time"
)

type PolicyIdentityReader interface {
	ListPolicySessions(context.Context, time.Time) ([]policy.Session, error)
}
type ScopedPolicyIdentityReader interface {
	ListPolicySessionsForScope(context.Context, time.Time, string, string) ([]policy.Session, error)
}

func policySession(s AccountSession) policy.Session {
	start, _ := time.Parse(time.RFC3339Nano, s.StartedAt)
	end, _ := time.Parse(time.RFC3339Nano, s.EndedAt)
	confirmed, _ := time.Parse(time.RFC3339Nano, s.LastConfirmedAt)
	return policy.Session{Status: s.SessionStatus, ID: s.SessionID, AccountID: s.AccountID, EndpointID: s.EndpointID, IP: s.IP, MAC: s.MAC, CampusID: s.CampusID, AccessDomain: s.AccessDomain, GroupID: s.GroupID, ProductID: s.ProductID, VLAN: s.VLAN, Source: s.Source, StartedAt: start, EndedAt: end, ConfirmedAt: confirmed, HeartbeatSeconds: s.HeartbeatSeconds, ReconcileSeconds: s.ReconcileSeconds, DeviceClass: s.DeviceClass, Confirmations: []time.Time{confirmed}}
}

// foldPolicySessions replays facts by event time, retaining separate login intervals.
// Only an explicit login after a known end may reopen a reused source session ID.
func foldPolicySessions(rows []policy.Session) []policy.Session {
	rows = append([]policy.Session(nil), rows...)
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].ConfirmedAt.Equal(rows[j].ConfirmedAt) {
			return rows[i].ConfirmedAt.Before(rows[j].ConfirmedAt)
		}
		// A stable tie break also makes ambiguous simultaneous observations conservative:
		// an end wins over a start at the same timestamp.
		if rows[i].EndedAt.IsZero() != rows[j].EndedAt.IsZero() {
			return rows[i].EndedAt.IsZero()
		}
		left, _ := json.Marshal(rows[i])
		right, _ := json.Marshal(rows[j])
		return string(left) < string(right)
	})
	type sessionKey struct{ source, sensor, campus, domain, id, ip string }
	latest := map[sessionKey]int{}
	out := []policy.Session{}
	for _, s := range rows {
		key := sessionKey{s.Source, s.SensorID, s.CampusID, s.AccessDomain, s.ID, s.IP}
		index, ok := latest[key]
		if ok {
			old := out[index]
			status := strings.ToLower(s.Status)
			login := status == "start" || status == "login" || status == "accounting-start" || status == "reconcile"
			if login && !old.EndedAt.IsZero() && s.ConfirmedAt.After(old.EndedAt) {
				latest[key] = len(out)
				out = append(out, s)
				continue
			}
			s.BindingConflict = s.BindingConflict || old.BindingConflict || (old.AccountID != "" && s.AccountID != "" && old.AccountID != s.AccountID)
			s.AccountID = firstNonEmpty(s.AccountID, old.AccountID)
			s.StartedAt = old.StartedAt
			if !old.EndedAt.IsZero() && (s.EndedAt.IsZero() || old.EndedAt.Before(s.EndedAt)) {
				s.EndedAt = old.EndedAt
			}
			s.EndpointID = firstNonEmpty(s.EndpointID, old.EndpointID)
			s.MAC = firstNonEmpty(s.MAC, old.MAC)
			s.GroupID = firstNonEmpty(s.GroupID, old.GroupID)
			s.ProductID = firstNonEmpty(s.ProductID, old.ProductID)
			s.DeviceClass = firstNonEmpty(s.DeviceClass, old.DeviceClass)
			s.VLAN = firstNonEmpty(s.VLAN, old.VLAN)
			snapshotIDs := append([]string{}, s.IdentitySnapshotIDs...)
			if len(snapshotIDs) == 0 {
				snapshotIDs = append(snapshotIDs, old.IdentitySnapshotIDs...)
			}
			sort.Strings(snapshotIDs)
			s.IdentitySnapshotIDs = snapshotIDs[:0]
			for _, id := range snapshotIDs {
				if id != "" && (len(s.IdentitySnapshotIDs) == 0 || s.IdentitySnapshotIDs[len(s.IdentitySnapshotIDs)-1] != id) {
					s.IdentitySnapshotIDs = append(s.IdentitySnapshotIDs, id)
				}
			}
			if s.HeartbeatSeconds <= 0 {
				s.HeartbeatSeconds = old.HeartbeatSeconds
			}
			if s.ReconcileSeconds <= 0 {
				s.ReconcileSeconds = old.ReconcileSeconds
			}
			confirmations := append(append([]time.Time(nil), old.Confirmations...), s.Confirmations...)
			sort.Slice(confirmations, func(i, j int) bool { return confirmations[i].Before(confirmations[j]) })
			s.Confirmations = nil
			for _, at := range confirmations {
				if len(s.Confirmations) == 0 || !s.Confirmations[len(s.Confirmations)-1].Equal(at) {
					s.Confirmations = append(s.Confirmations, at)
				}
			}
			out[index] = s
		} else {
			latest[key] = len(out)
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.AccountID != b.AccountID {
			return a.AccountID < b.AccountID
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if !a.StartedAt.Equal(b.StartedAt) {
			return a.StartedAt.Before(b.StartedAt)
		}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return string(x) < string(y)
	})
	return out
}
func policyRows(events []normalized.Event) []policy.Session {
	out := []policy.Session{}
	for _, e := range events {
		if e.Type != "identity" {
			continue
		}
		for _, s := range BuildIdentityState([]normalized.Event{e}).Sessions {
			row := policySession(s)
			row.SensorID = stringFromMap(e.Observer, "sensor_id")
			out = append(out, row)
		}
	}
	return out
}
func (s *FileStore) ListPolicySessions(ctx context.Context, at time.Time) ([]policy.Session, error) {
	runs, err := s.runs(ctx)
	if err != nil {
		return nil, err
	}
	rows := []policy.Session{}
	seen := map[string]bool{}
	for _, r := range runs {
		events, err := readNormalizedEvents(ctx, filepath.Join(r.Dir, "normalized.jsonl"), Query{From: at.Add(-7 * 24 * time.Hour).Format(time.RFC3339Nano), To: at.Format(time.RFC3339Nano), Limit: -1})
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			if !seen[e.EventID] {
				seen[e.EventID] = true
				rows = append(rows, policyRows([]normalized.Event{e})...)
			}
		}
	}
	return foldPolicySessions(rows), nil
}
func (s *DBStore) ListPolicySessions(ctx context.Context, at time.Time) ([]policy.Session, error) {
	return s.pg.ListPolicySessions(ctx, at)
}
func (s *DBStore) ListPolicySessionsForScope(ctx context.Context, at time.Time, campus, domain string) ([]policy.Session, error) {
	return s.pg.ListPolicySessionsForScope(ctx, at, campus, domain)
}
func (s *PostgresStore) ListPolicySessions(ctx context.Context, at time.Time) ([]policy.Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT session_data FROM policy_identity_observations WHERE observed_at >= $1 AND observed_at <= $2 ORDER BY observed_at,event_id`, at.Add(-7*24*time.Hour), at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []policy.Session{}
	for rows.Next() {
		var data []byte
		var s policy.Session
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	snapshots, err := s.identitySnapshots(ctx, at)
	if err != nil {
		return nil, err
	}
	return reconcileIdentitySessions(out, snapshots, at), nil
}
func (s *PostgresStore) ListPolicySessionsForScope(ctx context.Context, at time.Time, campus, domain string) ([]policy.Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT session_data FROM policy_identity_observations WHERE observed_at >= $1 AND observed_at <= $2 AND session_data->>'campus_id'=$3 AND session_data->>'access_domain'=$4 ORDER BY observed_at,event_id`, at.Add(-7*24*time.Hour), at, campus, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []policy.Session{}
	for rows.Next() {
		var data []byte
		var s policy.Session
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	snapshots, err := s.identitySnapshotsForScope(ctx, at, campus, domain)
	if err != nil {
		return nil, err
	}
	return reconcileIdentitySessions(out, snapshots, at), nil
}
func writePolicyIdentityEvents(ctx context.Context, tx *sql.Tx, events []normalized.Event) error {
	for _, e := range events {
		for _, s := range policyRows([]normalized.Event{e}) {
			raw, err := json.Marshal(s)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO policy_identity_observations(event_id,observed_at,account_id,session_id,session_data) VALUES($1,$2,$3,$4,$5) ON CONFLICT(event_id) DO NOTHING`, e.EventID, s.ConfirmedAt, s.AccountID, s.ID, raw); err != nil {
				return err
			}
		}
	}
	return nil
}
