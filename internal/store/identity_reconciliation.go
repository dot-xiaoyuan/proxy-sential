package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
)

// IdentityScope is the authority boundary of one complete online inventory.
type IdentityScope struct {
	Source       string `json:"source"`
	SensorID     string `json:"sensor_id"`
	CampusID     string `json:"campus_id"`
	AccessDomain string `json:"access_domain"`
}
type IdentitySnapshot struct {
	IdentityScope
	SnapshotID      string             `json:"snapshot_id"`
	ObservedAt      time.Time          `json:"observed_at"`
	IntervalSeconds int                `json:"reconcile_interval_seconds"`
	Sessions        []policy.Session   `json:"-"`
	Events          []normalized.Event `json:"events"`
}
type IdentitySourceStatus struct {
	Blocker string `json:"blocker,omitempty"`
	IdentityScope
	SnapshotID      string    `json:"snapshot_id"`
	ObservedAt      time.Time `json:"observed_at"`
	ReceivedAt      time.Time `json:"received_at"`
	IntervalSeconds int       `json:"reconcile_interval_seconds"`
	SessionCount    int       `json:"session_count"`
	State           string    `json:"state"`
	AgeSeconds      float64   `json:"age_seconds"`
}
type IdentityReconciler interface {
	CommitIdentitySnapshot(context.Context, IdentitySnapshot) (bool, error)
	IdentitySources(context.Context, time.Time) ([]IdentitySourceStatus, error)
}

var ErrIdentitySnapshotConflict = errors.New("snapshot identity or scope timestamp already has different content")

func scopeOf(s policy.Session) IdentityScope {
	return IdentityScope{s.Source, s.SensorID, s.CampusID, s.AccessDomain}
}
func reconcileIdentitySessions(facts []policy.Session, snapshots []IdentitySnapshot, at time.Time) []policy.Session {
	facts = append([]policy.Session(nil), facts...)
	sort.Slice(facts, func(i, j int) bool { return facts[i].ConfirmedAt.Before(facts[j].ConfirmedAt) })
	snapshots = append([]IdentitySnapshot(nil), snapshots...)
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].ObservedAt.Before(snapshots[j].ObservedAt) })
	rows := []policy.Session{}
	coverage := map[IdentityScope][]policy.IdentityCoverage{}
	cursor := 0
	for _, snapshot := range snapshots {
		if snapshot.ObservedAt.After(at) {
			continue
		}
		for cursor < len(facts) && !facts[cursor].ConfirmedAt.After(snapshot.ObservedAt) {
			rows = append(rows, facts[cursor])
			cursor++
		}
		rows = foldPolicySessions(rows)
		present := map[[3]string]bool{}
		for _, s := range snapshot.Sessions {
			present[[3]string{s.ID, s.IP, s.AccountID}] = true
		}
		for _, s := range rows {
			if scopeOf(s) != snapshot.IdentityScope || !s.EndedAt.IsZero() || present[[3]string{s.ID, s.IP, s.AccountID}] {
				continue
			}
			s.Status = "stop"
			s.EndedAt = snapshot.ObservedAt
			s.ConfirmedAt = snapshot.ObservedAt
			s.Confirmations = nil
			rows = append(rows, s)
		}
		rows = append(rows, snapshot.Sessions...)
		windows := coverage[snapshot.IdentityScope]
		until := snapshot.ObservedAt.Add(time.Duration(3*snapshot.IntervalSeconds) * time.Second)
		if len(windows) > 0 && !snapshot.ObservedAt.After(windows[len(windows)-1].To) {
			windows[len(windows)-1].To = until
		} else {
			windows = append(windows, policy.IdentityCoverage{From: snapshot.ObservedAt, To: until})
		}
		coverage[snapshot.IdentityScope] = windows
	}
	for ; cursor < len(facts); cursor++ {
		if !facts[cursor].ConfirmedAt.After(at) {
			rows = append(rows, facts[cursor])
		}
	}
	rows = foldPolicySessions(rows)
	for i, s := range rows {
		rows[i].SourceCoverage = coverage[scopeOf(s)]
	}
	return rows
}

func (s *DBStore) CommitIdentitySnapshot(ctx context.Context, snapshot IdentitySnapshot) (bool, error) {
	return s.pg.CommitIdentitySnapshot(ctx, snapshot)
}
func (s *DBStore) IdentitySources(ctx context.Context, at time.Time) ([]IdentitySourceStatus, error) {
	return s.pg.IdentitySources(ctx, at)
}

// The inventory and its status become visible in one PostgreSQL commit. Raw
// standardized events are retained with the snapshot for replay and explanation.
func (s *PostgresStore) CommitIdentitySnapshot(ctx context.Context, snapshot IdentitySnapshot) (bool, error) {
	if snapshot.Source == "" || snapshot.SensorID == "" || snapshot.CampusID == "" || snapshot.AccessDomain == "" || snapshot.SnapshotID == "" || snapshot.ObservedAt.IsZero() || snapshot.IntervalSeconds < 1 || snapshot.IntervalSeconds > 86400 {
		return false, fmt.Errorf("invalid snapshot scope, time, identity or interval")
	}
	snapshot.Events = append([]normalized.Event{}, snapshot.Events...)
	snapshot.Sessions = policyRows(snapshot.Events)
	if len(snapshot.Sessions) != len(snapshot.Events) {
		return false, fmt.Errorf("every inventory event must identify exactly one session")
	}
	seen := map[[2]string]bool{}
	for _, session := range snapshot.Sessions {
		key := [2]string{session.ID, session.IP}
		if session.Status != "reconcile" || session.HeartbeatSeconds != snapshot.IntervalSeconds || scopeOf(session) != snapshot.IdentityScope || session.ID == "" || session.AccountID == "" || !session.EndedAt.IsZero() || !session.ConfirmedAt.Equal(snapshot.ObservedAt) || seen[key] {
			return false, fmt.Errorf("invalid or duplicate inventory session")
		}
		seen[key] = true
	}
	sort.Slice(snapshot.Events, func(i, j int) bool { return snapshot.Events[i].EventID < snapshot.Events[j].EventID })
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	// Scope lock serializes competing snapshots without locking the packet ingest path.
	scopeJSON, _ := json.Marshal(snapshot.IdentityScope)
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 7135))`, string(scopeJSON)); err != nil {
		return false, err
	}
	var old string
	err = tx.QueryRowContext(ctx, `SELECT content_sha256 FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND (snapshot_id=$5 OR observed_at=$6)`, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.SnapshotID, snapshot.ObservedAt).Scan(&old)
	if err == nil {
		if old != digest {
			return false, ErrIdentitySnapshotConflict
		}
		return false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_full_snapshots(source,sensor_id,campus_id,access_domain,snapshot_id,observed_at,interval_seconds,session_count,content_sha256,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, snapshot.Source, snapshot.SensorID, snapshot.CampusID, snapshot.AccessDomain, snapshot.SnapshotID, snapshot.ObservedAt, snapshot.IntervalSeconds, len(snapshot.Sessions), digest, raw)
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'identity.snapshot.commit',$3,'success',now())`, "identity-snapshot-"+digest, "identity-integration:"+snapshot.Source, string(scopeJSON)+"/"+snapshot.SnapshotID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *PostgresStore) IdentitySources(ctx context.Context, at time.Time) ([]IdentitySourceStatus, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT ON(source,sensor_id,campus_id,access_domain) source,sensor_id,campus_id,access_domain,snapshot_id,observed_at,received_at,interval_seconds,session_count FROM identity_full_snapshots WHERE observed_at<=$1 ORDER BY source,sensor_id,campus_id,access_domain,observed_at DESC`, at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentitySourceStatus{}
	for rows.Next() {
		var v IdentitySourceStatus
		if err = rows.Scan(&v.Source, &v.SensorID, &v.CampusID, &v.AccessDomain, &v.SnapshotID, &v.ObservedAt, &v.ReceivedAt, &v.IntervalSeconds, &v.SessionCount); err != nil {
			return nil, err
		}
		v.AgeSeconds = max(0, at.Sub(v.ObservedAt).Seconds())
		v.State = "healthy"
		if v.AgeSeconds >= float64(3*v.IntervalSeconds) {
			v.State = "interrupted"
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) identitySnapshots(ctx context.Context, at time.Time) ([]IdentitySnapshot, error) {
	// Include the most recent pre-window inventory as a baseline and all in-window
	// snapshots, so long-lived logins and late pre-snapshot facts remain bounded.
	rows, err := s.db.QueryContext(ctx, `SELECT document FROM identity_full_snapshots WHERE observed_at BETWEEN $1 AND $2 UNION ALL SELECT document FROM (SELECT DISTINCT ON(source,sensor_id,campus_id,access_domain) document FROM identity_full_snapshots WHERE observed_at<$1 ORDER BY source,sensor_id,campus_id,access_domain,observed_at DESC) baseline`, at.Add(-7*24*time.Hour), at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentitySnapshot{}
	for rows.Next() {
		var raw []byte
		var v IdentitySnapshot
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		v.Sessions = policyRows(v.Events)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) identitySnapshotsForScope(ctx context.Context, at time.Time, campus, domain string) ([]IdentitySnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT document FROM identity_full_snapshots WHERE observed_at BETWEEN $1 AND $2 AND campus_id=$3 AND access_domain=$4 UNION ALL SELECT document FROM (SELECT DISTINCT ON(source,sensor_id,campus_id,access_domain) document FROM identity_full_snapshots WHERE observed_at<$1 AND campus_id=$3 AND access_domain=$4 ORDER BY source,sensor_id,campus_id,access_domain,observed_at DESC) baseline`, at.Add(-7*24*time.Hour), at, campus, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentitySnapshot{}
	for rows.Next() {
		var raw []byte
		var v IdentitySnapshot
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		v.Sessions = policyRows(v.Events)
		out = append(out, v)
	}
	return out, rows.Err()
}
