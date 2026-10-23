package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
)

const snapshotLogInsertSQL = `INSERT INTO identity_snapshot_log(source,sensor_id,campus_id,access_domain,snapshot_id,observed_at,interval_seconds,session_count,content_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`

const snapshotLogProjectedSQL = `UPDATE identity_snapshot_log SET projected=true WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5 AND NOT projected`

// snapshotMeta is one identity_snapshot_log row.
type snapshotMeta struct {
	CaptureStartedAt time.Time
	Scope            IdentityScope
	SnapshotID       string
	ObservedAt       time.Time
	IntervalSeconds  int
}

// snapshotDocument returns the canonical stored document of a snapshot and its content digest.
func snapshotDocument(snapshot IdentitySnapshot) ([]byte, string, error) {
	snapshot.Events = append([]normalized.Event{}, snapshot.Events...)
	sort.Slice(snapshot.Events, func(i, j int) bool { return snapshot.Events[i].EventID < snapshot.Events[j].EventID })
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256(raw)
	return raw, hex.EncodeToString(hash[:]), nil
}

func (s *PostgresStore) snapshotDigest(snapshot IdentitySnapshot) (string, error) {
	_, digest, err := snapshotDocument(snapshot)
	return digest, err
}

// coverageFromLog derives per-scope source coverage exactly as the per-snapshot computation did: a
// snapshot covers three of its intervals, and windows that touch or overlap merge.
func coverageFromLog(log []snapshotMeta, at time.Time) map[IdentityScope][]policy.IdentityCoverage {
	ordered := append([]snapshotMeta(nil), log...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ObservedAt.Before(ordered[j].ObservedAt) })
	coverage := map[IdentityScope][]policy.IdentityCoverage{}
	for _, snapshot := range ordered {
		if snapshot.ObservedAt.After(at) {
			continue
		}
		windows := coverage[snapshot.Scope]
		until := snapshot.ObservedAt.Add(time.Duration(3*snapshot.IntervalSeconds) * time.Second)
		if len(windows) > 0 && !snapshot.ObservedAt.After(windows[len(windows)-1].To) {
			windows[len(windows)-1].To = until
		} else {
			windows = append(windows, policy.IdentityCoverage{From: snapshot.ObservedAt, To: until})
		}
		coverage[snapshot.Scope] = windows
	}
	return coverage
}
