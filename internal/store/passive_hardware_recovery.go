package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

// HardwareDHCPRecovery is temporary repair input. The original Zeek event ID
// binds the complete record bytes, including the VLAN, to the saved evidence.
type HardwareDHCPRecovery struct {
	Header    string `json:"header"`
	RawLine   string `json:"raw_line"`
	RawSHA256 string `json:"raw_sha256"`
}

func RecoverHardwareDHCPObservation(original discovery.Observation, proof HardwareDHCPRecovery) (discovery.Observation, error) {
	fail := func(reason string) (discovery.Observation, error) {
		return discovery.Observation{}, fmt.Errorf("DHCP recovery: %s", reason)
	}
	if original.Origin != "dhcp" || original.Withdrawn || original.VRF != "" ||
		original.Evidence.Source != "zeek" || original.Evidence.SourceEventType != "dhcp" ||
		original.EventID != original.Evidence.EventID ||
		passiveString(original.Evidence.Observer, "capture_scope_issue") != "" ||
		original.Node == "" || original.Site == "" || original.Domain == "" {
		return fail("source is not an eligible scoped Zeek DHCP observation")
	}
	if len(proof.RawLine) == 0 || len(proof.RawLine) > HardwareRepairMaxRowBytes ||
		len(proof.Header) > 8192 || strings.ContainsAny(proof.RawLine, "\r\n") ||
		repairHash([]byte(proof.RawLine)) != proof.RawSHA256 ||
		original.EventID != "zeek-"+proof.RawSHA256[:24] {
		return fail("original record hash does not match the saved event")
	}
	for _, line := range strings.Split(strings.TrimSuffix(proof.Header, "\n"), "\n") {
		if !strings.HasPrefix(line, "#") {
			return fail("header contains data")
		}
	}
	var converted bytes.Buffer
	stats, err := zeek.Convert(strings.NewReader(proof.Header+"\n"+proof.RawLine+"\n"), &converted, zeek.Options{SensorID: original.Node, LogKind: "dhcp"})
	if err != nil || stats.Emitted != 1 {
		return fail("original record cannot be decoded uniquely")
	}
	var event normalized.Event
	if err = json.Unmarshal(bytes.TrimSpace(converted.Bytes()), &event); err != nil {
		return fail("invalid decoded event")
	}
	if event.EventID != original.EventID {
		return fail("original event or timestamp differs")
	}
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	savedAt, savedErr := time.Parse(time.RFC3339Nano, original.Evidence.Timestamp)
	// The ClickHouse input and PostgreSQL timestamps retain microseconds.
	if err != nil || savedErr != nil || !at.Truncate(time.Microsecond).Equal(original.ObservedAt.Truncate(time.Microsecond)) || !savedAt.Truncate(time.Microsecond).Equal(original.ObservedAt.Truncate(time.Microsecond)) {
		return fail("observation timestamp differs")
	}
	p := event.Payload
	if passiveString(event.Subject, "ip") != original.IP ||
		!strings.EqualFold(passiveString(event.Subject, "mac"), original.MAC) ||
		passiveString(p, "assigned_addr") != original.IP ||
		p["discovery_scope_conflict"] == true {
		return fail("address, MAC or capture scope differs")
	}
	for _, key := range []string{"uids", "vendor_class", "msg_types", "lease_time"} {
		if passiveString(p, key) == "" || passiveString(p, key) != passiveString(original.Evidence.Payload, key) {
			return fail("original " + key + " differs")
		}
	}
	vlan := passiveString(p, "dhcp_capture_vlan")
	if vlan == "" || original.VLAN != "" && original.VLAN != vlan {
		return fail("VLAN absent or conflicting")
	}
	if prior := passiveString(original.Evidence.Payload, "dhcp_capture_vlan"); prior != "" && prior != vlan {
		return fail("stored capture VLAN conflicts")
	}
	raw, err := json.Marshal(original)
	if err != nil {
		return discovery.Observation{}, err
	}
	var restored discovery.Observation
	if err = json.Unmarshal(raw, &restored); err != nil {
		return discovery.Observation{}, err
	}
	restored.VLAN = vlan
	restored.Evidence.Payload["dhcp_capture_vlan"] = vlan
	restored.Evidence.Payload["scope_recovery"] = map[string]any{"original_device_key": original.Key(), "original_event_id": original.EventID, "raw_sha256": proof.RawSHA256}
	fact, err := discovery.HardwareFactFromObservation(restored)
	if err != nil || fact == nil || len(fact.Signals) == 0 {
		return fail("recovered record has no usable DHCP product evidence")
	}
	return restored, nil
}

// applyHardwareDHCPCorrection changes only the derived latest index and facts.
// Immutable observations and original normalized events retain their bytes.
func applyHardwareDHCPCorrection(ctx context.Context, tx *sql.Tx, entry HardwareRepairEntry, restored discovery.Observation) (bool, string, error) {
	original := *entry.Observation
	oldFact, err := discovery.HardwareFactFromObservation(original)
	if err != nil || oldFact == nil {
		return false, "", fmt.Errorf("original DHCP fact is invalid")
	}
	newKey := restored.Key()
	keys := entry.Key
	var current []byte
	err = tx.QueryRowContext(ctx, `SELECT data::text FROM discovery_observation_latest
 WHERE device_key=$1 AND source_id=$2 AND origin=$3 AND service_type=$4 AND port=$5 FOR UPDATE`, keys[0], keys[1], keys[2], keys[3], keys[4]).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		var proof string
		err = tx.QueryRowContext(ctx, `SELECT coalesce(data->'evidence'->'payload'->'scope_recovery'->>'raw_sha256','')
 FROM discovery_observation_latest WHERE device_key=$1 AND source_id=$2 AND origin=$3 AND service_type=$4 AND port=$5 AND id=$6`,
			newKey, keys[1], keys[2], keys[3], keys[4], restored.ID).Scan(&proof)
		if errors.Is(err, sql.ErrNoRows) {
			return false, "source_changed", nil
		}
		if err != nil {
			return false, "", err
		}
		if proof == entry.DHCPRecovery.RawSHA256 {
			return true, "already_recovered", nil
		}
		return false, "source_changed", nil
	}
	if err != nil {
		return false, "", err
	}
	if repairHash(current) != entry.SourceSHA256 {
		return false, "source_changed", nil
	}
	if original.VLAN == restored.VLAN {
		return true, "scope_already_present", nil
	}
	encoded, err := json.Marshal(restored)
	if err != nil {
		return false, "", err
	}
	// A concurrent current observation always wins over an older correction.
	_, err = tx.ExecContext(ctx, `INSERT INTO discovery_observation_latest(device_key,source_id,origin,service_type,port,id,observed_at,valid_until,withdrawn,data)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
 ON CONFLICT(device_key,source_id,origin,service_type,port) DO UPDATE SET
 id=EXCLUDED.id,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,data=EXCLUDED.data
 WHERE (EXCLUDED.observed_at,EXCLUDED.id)>(discovery_observation_latest.observed_at,discovery_observation_latest.id)`,
		newKey, keys[1], keys[2], keys[3], keys[4], restored.ID, restored.ObservedAt, restored.ValidUntil, restored.Withdrawn, string(encoded))
	if err != nil {
		return false, "", err
	}
	var target []byte
	err = tx.QueryRowContext(ctx, `SELECT data FROM discovery_observation_latest WHERE device_key=$1 AND source_id=$2 AND origin=$3 AND service_type=$4 AND port=$5 FOR UPDATE`,
		newKey, keys[1], keys[2], keys[3], keys[4]).Scan(&target)
	if err != nil {
		return false, "", err
	}
	var latest discovery.Observation
	if err = json.Unmarshal(target, &latest); err != nil {
		return false, "", err
	}
	if latest.ObservedAt.Before(original.ObservedAt) || latest.ObservedAt.Equal(original.ObservedAt) && latest.EventID != original.EventID {
		return false, "target_scope_conflict", nil
	}
	// Revoke only facts derived from this exact original event. Other claims in
	// the old scope remain available and must never be merged by MAC alone.
	recoveryAudit, err := json.Marshal(map[string]any{"new_device_key": newKey, "raw_sha256": entry.DHCPRecovery.RawSHA256, "original_source_sha256": entry.SourceSHA256})
	if err != nil {
		return false, "", err
	}
	_, err = tx.ExecContext(ctx, `WITH changed AS (
 UPDATE passive_hardware_facts SET revoked=true,data=jsonb_set(jsonb_set(data,'{revoked}','true'::jsonb),'{scope_recovery}',$3::jsonb)
 WHERE identity_key=$1 AND evidence_id=$2 AND NOT revoked RETURNING identity_key,sensor_id)
 INSERT INTO passive_hardware_dirty(identity_key,sensor_id,reason)
 SELECT DISTINCT identity_key,sensor_id,'scope_correction' FROM changed ON CONFLICT(identity_key) DO NOTHING`, oldFact.IdentityKey, original.EventID, string(recoveryAudit))
	if err != nil {
		return false, "", err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM discovery_observation_latest WHERE device_key=$1 AND source_id=$2 AND origin=$3 AND service_type=$4 AND port=$5 AND id=$6`,
		keys[0], keys[1], keys[2], keys[3], keys[4], original.ID)
	if err != nil {
		return false, "", err
	}
	if latest.Withdrawn || latest.ObservedAt.After(original.ObservedAt) {
		return false, "superseded_by_current_observation", nil
	}
	return true, "scope_recovered", nil
}
