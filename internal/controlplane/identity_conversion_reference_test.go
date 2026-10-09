package controlplane

// Frozen r65 JSON pipeline used only as an independent differential replay.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	identityadapter "proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
	"strconv"
	"strings"
	"time"
)

func prepareIdentitySnapshotJSONReference(request identitySnapshotRequest, id string, now time.Time, maxRecords int) (store.IdentitySnapshot, error) {
	result := store.IdentitySnapshot{IdentityScope: request.IdentityScope, SnapshotID: id, ObservedAt: request.ObservedAt.UTC(), IntervalSeconds: request.IntervalSeconds, Events: []normalized.Event{}}
	if request.Records == nil || !request.Complete || request.ExpectedCount == nil || *request.ExpectedCount != len(request.Records) || len(request.Records) > maxRecords {
		return result, fmt.Errorf("complete inventory and matching expected_count (0..%d) required", maxRecords)
	}
	for _, value := range []string{id, request.Source, request.SensorID} {
		if strings.TrimSpace(value) == "" || len(value) > 200 || value != strings.TrimSpace(value) {
			return result, fmt.Errorf("explicit source, sensor and snapshot ID required (maximum 200 characters)")
		}
	}
	for _, value := range []string{request.CampusID, request.AccessDomain} {
		if len(value) > 200 || value != strings.TrimSpace(value) {
			return result, fmt.Errorf("invalid optional identity scope")
		}
	}
	if (request.CampusID == "" || request.AccessDomain == "") && !strings.HasPrefix(request.Source, "srun4k:") {
		return result, fmt.Errorf("campus_id and access_domain are required outside managed srun4k sources")
	}
	if result.ObservedAt.IsZero() || result.ObservedAt.After(now) || result.ObservedAt.Before(now.Add(-7*24*time.Hour)) || result.ObservedAt.Nanosecond()%1000 != 0 {
		return result, fmt.Errorf("observed_at must be within the past seven days with at most microsecond precision")
	}
	maxInterval := 86400
	if strings.HasPrefix(request.Source, "srun4k:") {
		maxInterval = 604800
	}
	if request.IntervalSeconds < 1 || request.IntervalSeconds > maxInterval {
		return result, fmt.Errorf("reconcile_interval_seconds must be between 1 and %d", maxInterval)
	}
	var input, output bytes.Buffer
	encoder := json.NewEncoder(&input)
	seen := map[[2]string]bool{}
	for i, record := range request.Records {
		fields := map[string]string{}
		for k, v := range record {
			fields[k] = v
		}
		ip, err := netip.ParseAddr(fields["ip"])
		if err != nil || ip.IsUnspecified() || ip.Zone() != "" || strings.TrimSpace(fields["session_id"]) == "" || strings.TrimSpace(fields["account_id"]) == "" || fields["session_id"] != strings.TrimSpace(fields["session_id"]) || fields["account_id"] != strings.TrimSpace(fields["account_id"]) {
			return result, fmt.Errorf("record %d requires session_id, account_id and a valid IP", i+1)
		}
		fields["ip"] = ip.Unmap().String()
		key := [2]string{fields["session_id"], fields["ip"]}
		if seen[key] {
			return result, fmt.Errorf("duplicate session at record %d", i+1)
		}
		seen[key] = true
		fixed := map[string]string{"entity_role": "endpoint", "source": request.Source, "sensor_id": request.SensorID, "campus_id": request.CampusID, "access_domain": request.AccessDomain, "timestamp": result.ObservedAt.Format(time.RFC3339Nano), "session_status": "reconcile", "action": "reconcile", "heartbeat_interval_seconds": strconv.Itoa(request.IntervalSeconds), "reconcile_interval_seconds": strconv.Itoa(request.IntervalSeconds)}
		for k, v := range fixed {
			if old := fields[k]; old != "" && old != v {
				return result, fmt.Errorf("record %d conflicts with snapshot field %s", i+1, k)
			}
			fields[k] = v
		}
		if err = encoder.Encode(fields); err != nil {
			return result, err
		}
	}
	stats, err := identityadapter.Convert(&input, &output, identityadapter.Options{Source: request.Source, SensorID: request.SensorID})
	if err != nil {
		return result, err
	}
	if stats.Emitted != len(request.Records) || stats.Skipped != 0 || stats.Malformed != 0 {
		return result, fmt.Errorf("inventory contains invalid identity records")
	}
	decoder := json.NewDecoder(&output)
	for decoder.More() {
		var e normalized.Event
		if err = decoder.Decode(&e); err != nil {
			return result, err
		}
		e.RawRef = map[string]any{"snapshot_id": id, "source": request.Source, "sensor_id": request.SensorID, "campus_id": request.CampusID, "access_domain": request.AccessDomain}
		result.Events = append(result.Events, e)
	}
	return result, nil
}
