package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"time"
)

// ApplyDHCPMessageReplay uses the regular discovery writer for a bounded set
// of verified original records. It never moves the live event-time cursor.
// The caller must re-read and hash each original before calling and persist
// its checkpoint only after this succeeds; replay after a crash is idempotent.
func ApplyDHCPMessageReplay(ctx context.Context, db *sql.DB, sensor, cidrs string, events []normalized.Event) ([]HardwareRepairOutcome, error) {
	return applyVerifiedOriginalReplay(ctx, db, sensor, cidrs, events, "dhcp-message")
}

// ApplyRTSPOriginalReplay retains verified client/server ownership and uses the
// regular bounded writer; it cannot manufacture a MAC or move the live cursor.
func ApplyRTSPOriginalReplay(ctx context.Context, db *sql.DB, sensor, cidrs string, events []normalized.Event) ([]HardwareRepairOutcome, error) {
	return applyVerifiedOriginalReplay(ctx, db, sensor, cidrs, events, "rtsp-device")
}

func applyVerifiedOriginalReplay(ctx context.Context, db *sql.DB, sensor, cidrs string, events []normalized.Event, kind string) ([]HardwareRepairOutcome, error) {
	if !discovery.HardwareProjectionEnabled() || sensor == "" || len(events) > 50 {
		return nil, fmt.Errorf("original replay requires hardware gate, sensor and at most 50 events")
	}
	raw, err := json.Marshal(events)
	if err != nil || len(raw) > HardwareRepairMaxBatchBytes {
		return nil, fmt.Errorf("original replay exceeds 1 MiB")
	}
	scope, err := parsePassiveDiscoveryScope(cidrs)
	if err != nil {
		return nil, err
	}
	outcomes := make([]HardwareRepairOutcome, 0, len(events))
	for i, e := range events {
		hash := passiveString(e.RawRef, "content_sha256")
		if e.Source != "zeek" || !((kind == "dhcp-message" && e.SourceEventType == "dhcp" && passiveString(e.Payload, "dhcp_log_kind") == "dhcp-message") || (kind == "rtsp-device" && e.SourceEventType == "rtsp")) || passiveString(e.Observer, "sensor_id") != sensor || passiveInterface(e) == "" || len(hash) != 64 || e.EventID != "zeek-"+hash[:24] || passiveString(e.RawRef, "original_file_id") == "" {
			return nil, fmt.Errorf("original replay source not verified at entry %d", i)
		}
		o, reason := passiveObservation(e, scope)
		r := HardwareRepairOutcome{Index: i, ObservationID: o.ID, EventID: e.EventID, SourceSHA256: hash, Status: "excluded", Reason: reason}
		if reason == "" {
			r.Status = "admitted"
			r.Reason = "normal_discovery_pipeline"
		}
		outcomes = append(outcomes, r)
	}
	work, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: sensor}}
	if _, err = s.processPassiveDiscoveryBatch(work, events, scope); err != nil {
		return nil, err
	}
	return outcomes, nil
}
