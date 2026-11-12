package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"proxy-sentinel/internal/discovery"
)

const (
	HardwareRepairSchema           = "passive-hardware-retained-latest-repair/v1"
	HardwareRepairMaxRows          = 10000
	HardwareRepairMaxSnapshotBytes = 16 << 20
	HardwareRepairMaxRowBytes      = 64 << 10
	HardwareRepairMaxBatchBytes    = 1 << 20
)

// The window is event time, not ingestion time. This one-off repair cannot
// recover observations overwritten before this retained-latest snapshot.
type HardwareRepairWindow struct {
	Sensor string    `json:"sensor"`
	From   time.Time `json:"from"`
	Until  time.Time `json:"until_exclusive"`
}
type HardwareRepairManifest struct {
	SchemaVersion string                `json:"schema_version"`
	Window        HardwareRepairWindow  `json:"window"`
	SnapshotAt    time.Time             `json:"snapshot_at"`
	Entries       []HardwareRepairEntry `json:"entries"`
}

// Observation is a frozen, bounded normalized input with references, never a
// copied packet/XML. It is needed only until the recoverable job is reconciled.
// SourceSHA256 identifies the exact retained row, InputSHA256 the decoded input.
type HardwareRepairEntry struct {
	Key            [5]string              `json:"latest_key"`
	ObservationID  string                 `json:"observation_id"`
	EventID        string                 `json:"event_id"`
	ObservedAt     time.Time              `json:"observed_at"`
	RawRef         map[string]any         `json:"raw_ref,omitempty"`
	SourceSHA256   string                 `json:"source_sha256"`
	InputSHA256    string                 `json:"input_sha256,omitempty"`
	ExcludedReason string                 `json:"excluded_reason,omitempty"`
	Observation    *discovery.Observation `json:"observation,omitempty"`
}
type HardwareRepairOutcome struct {
	Index         int    `json:"index"`
	ObservationID string `json:"observation_id"`
	EventID       string `json:"event_id"`
	SourceSHA256  string `json:"source_sha256"`
	Status        string `json:"status"`
	Reason        string `json:"reason,omitempty"`
	IdentityKey   string `json:"identity_key,omitempty"`
	FactKey       string `json:"fact_key,omitempty"`
}
type HardwareRepairTxStarter interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

func repairHash(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func (w HardwareRepairWindow) validate() error {
	if w.Sensor == "" || w.From.IsZero() || !w.Until.After(w.From) || w.Until.Sub(w.From) > 30*24*time.Hour {
		return fmt.Errorf("repair requires sensor and a fixed nonempty event-time window of at most 30 days")
	}
	return nil
}
func makeHardwareRepairEntry(key [5]string, raw []byte, o discovery.Observation) HardwareRepairEntry {
	e := HardwareRepairEntry{Key: key, ObservationID: o.ID, EventID: o.EventID, ObservedAt: o.ObservedAt, RawRef: o.Evidence.RawRef, SourceSHA256: repairHash(raw)}
	switch {
	case o.EventID == "" || len(o.Evidence.RawRef) == 0:
		e.ExcludedReason = "missing_source_reference"
	case passiveString(o.Evidence.Observer, "capture_scope_issue") != "":
		e.ExcludedReason = "capture_scope_issue"
	case o.Node == "" || o.Site == "" || o.Domain == "":
		e.ExcludedReason = "missing_scope"
	case o.Evidence.EventID != "" && o.EventID != o.Evidence.EventID:
		e.ExcludedReason = "event_id_mismatch"
	default:
		e.Observation = &o
		b, _ := json.Marshal(o)
		e.InputSHA256 = repairHash(b)
	}
	return e
}
func (m HardwareRepairManifest) Validate() error {
	if err := m.Window.validate(); err != nil {
		return err
	}
	if m.SchemaVersion != HardwareRepairSchema || m.SnapshotAt.Before(m.Window.Until) || len(m.Entries) > HardwareRepairMaxRows {
		return fmt.Errorf("invalid repair snapshot or row bound")
	}
	seen := map[[5]string]bool{}
	for _, e := range m.Entries {
		if seen[e.Key] || e.Key[0] == "" || e.ObservationID == "" || len(e.SourceSHA256) != 64 || e.ObservedAt.Before(m.Window.From) || !e.ObservedAt.Before(m.Window.Until) {
			return fmt.Errorf("invalid or duplicate frozen source entry")
		}
		seen[e.Key] = true
		if e.Observation == nil {
			if e.ExcludedReason == "" {
				return fmt.Errorf("frozen entry has neither input nor exclusion")
			}
			continue
		}
		o := e.Observation
		b, err := json.Marshal(o)
		if err != nil || len(b) > HardwareRepairMaxRowBytes || repairHash(b) != e.InputSHA256 || o.Node != m.Window.Sensor || o.SourceID != e.Key[1] || o.Origin != e.Key[2] || o.ID != e.ObservationID || o.EventID != e.EventID || !o.ObservedAt.Equal(e.ObservedAt) || o.EventID == "" || len(o.Evidence.RawRef) == 0 || e.ExcludedReason != "" {
			return fmt.Errorf("frozen source input changed or exceeds bound")
		}
		expected := makeHardwareRepairEntry(e.Key, b, *o)
		if expected.ExcludedReason != "" {
			return fmt.Errorf("frozen source is not eligible: %s", expected.ExcludedReason)
		}
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > 2*HardwareRepairMaxSnapshotBytes {
		return fmt.Errorf("repair manifest exceeds 32 MiB")
	}
	return nil
}

// SnapshotHardwareRepair takes one bounded read-only snapshot, including an
// explicit exclusion record for every missing reference. No runtime cursor,
// applied migration or source observation is changed.
func SnapshotHardwareRepair(ctx context.Context, db HardwareRepairTxStarter, w HardwareRepairWindow) (HardwareRepairManifest, error) {
	m := HardwareRepairManifest{SchemaVersion: HardwareRepairSchema, Window: w, Entries: []HardwareRepairEntry{}}
	if err := w.validate(); err != nil {
		return m, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return m, err
	}
	defer tx.Rollback()
	var count, total, largest int64
	err = tx.QueryRowContext(ctx, `SELECT now(),count(*),coalesce(sum(octet_length(data::text)),0),coalesce(max(octet_length(data::text)),0) FROM (
 SELECT data FROM discovery_observation_latest WHERE data->>'node'=$1 AND observed_at>=$2 AND observed_at<$3
 ORDER BY device_key COLLATE "C",source_id COLLATE "C",origin COLLATE "C",service_type COLLATE "C",port COLLATE "C" LIMIT $4) bounded`, w.Sensor, w.From, w.Until, HardwareRepairMaxRows+1).Scan(&m.SnapshotAt, &count, &total, &largest)
	if err != nil {
		return m, err
	}
	if m.SnapshotAt.Before(w.Until) || count > HardwareRepairMaxRows || total > HardwareRepairMaxSnapshotBytes || largest > HardwareRepairMaxRowBytes {
		return m, fmt.Errorf("repair snapshot exceeds time/rows/bytes bounds: rows=%d bytes=%d max_row=%d", count, total, largest)
	}
	rows, err := tx.QueryContext(ctx, `SELECT device_key,source_id,origin,service_type,port,id,observed_at,data FROM discovery_observation_latest
 WHERE data->>'node'=$1 AND observed_at>=$2 AND observed_at<$3
 ORDER BY device_key COLLATE "C",source_id COLLATE "C",origin COLLATE "C",service_type COLLATE "C",port COLLATE "C" LIMIT $4`, w.Sensor, w.From, w.Until, HardwareRepairMaxRows+1)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var key [5]string
		var raw []byte
		var sourceID string
		var sourceTime time.Time
		var o discovery.Observation
		if err = rows.Scan(&key[0], &key[1], &key[2], &key[3], &key[4], &sourceID, &sourceTime, &raw); err != nil {
			rows.Close()
			return m, err
		}
		if len(raw) > HardwareRepairMaxRowBytes {
			rows.Close()
			return m, fmt.Errorf("repair source row exceeds 64 KiB")
		}
		if err = json.Unmarshal(raw, &o); err != nil {
			rows.Close()
			return m, err
		}
		// pgx stores PostgreSQL timestamptz at microsecond precision; retain the
		// original normalized timestamp in the manifest without rewriting it.
		if o.ID != sourceID || !o.ObservedAt.Truncate(time.Microsecond).Equal(sourceTime) || o.Node != w.Sensor || o.SourceID != key[1] || o.Origin != key[2] {
			rows.Close()
			return m, fmt.Errorf("retained source columns disagree with payload")
		}
		m.Entries = append(m.Entries, makeHardwareRepairEntry(key, raw, o))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return m, err
	}
	if int64(len(m.Entries)) != count {
		return m, fmt.Errorf("repair snapshot row count changed")
	}
	if err = m.Validate(); err != nil {
		return m, err
	}
	if err = tx.Commit(); err != nil {
		return m, err
	}
	return m, nil
}

// ApplyHardwareRepairBatch reuses production event-time ownership and fact
// upserts. Returned outcomes exist only after commit; a timeout/commit error
// leaves the caller's checkpoint unchanged. Replaying a committed batch after
// a checkpoint crash is safe under the normal fact conflict rules.
func ApplyHardwareRepairBatch(ctx context.Context, db HardwareRepairTxStarter, m HardwareRepairManifest, start, limit int) ([]HardwareRepairOutcome, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if start < 0 || start > len(m.Entries) || limit < 1 || limit > 50 {
		return nil, fmt.Errorf("invalid repair batch position/limit (maximum 50)")
	}
	end := start
	bytes := 0
	for end < len(m.Entries) && end < start+limit {
		raw, err := json.Marshal(m.Entries[end])
		if err != nil {
			return nil, err
		}
		if len(raw) > HardwareRepairMaxBatchBytes {
			return nil, fmt.Errorf("repair entry exceeds 1 MiB")
		}
		if bytes+len(raw) > HardwareRepairMaxBatchBytes {
			break
		}
		bytes += len(raw)
		end++
	}
	if end == start {
		return []HardwareRepairOutcome{}, nil
	}
	work, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	tx, err := db.BeginTx(work, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(work, `SET LOCAL lock_timeout='250ms'`); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(work, `SET LOCAL statement_timeout='3500ms'`); err != nil {
		return nil, err
	}
	outcomes := make([]HardwareRepairOutcome, 0, end-start)
	observations := []discovery.Observation{}
	for index := start; index < end; index++ {
		e := m.Entries[index]
		r := HardwareRepairOutcome{Index: index, ObservationID: e.ObservationID, EventID: e.EventID, SourceSHA256: e.SourceSHA256, Status: "excluded", Reason: e.ExcludedReason}
		if e.Observation != nil {
			o := *e.Observation
			o, err = resolveHardwareOwnership(work, tx, o)
			if err != nil {
				return nil, err
			}
			f, err := discovery.HardwareFactFromObservation(o)
			if err != nil {
				return nil, err
			}
			if f == nil {
				r.Reason = "identity_or_protocol_not_verified"
			} else {
				r.Status = "admitted"
				r.Reason = "enqueued_or_already_present"
				r.IdentityKey = f.IdentityKey
				r.FactKey = f.FactKey
				observations = append(observations, o)
			}
		}
		outcomes = append(outcomes, r)
	}
	if err = discovery.EnqueueHardwareObservations(work, tx, observations); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return outcomes, nil
}
