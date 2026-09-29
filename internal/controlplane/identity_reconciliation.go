package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	identityadapter "proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

type identitySnapshotRequest struct {
	store.IdentityScope
	ObservedAt      time.Time           `json:"observed_at"`
	IntervalSeconds int                 `json:"reconcile_interval_seconds"`
	Complete        bool                `json:"complete"`
	ExpectedCount   *int                `json:"expected_count"`
	Records         []map[string]string `json:"records"`
}

func prepareIdentitySnapshot(request identitySnapshotRequest, id string, now time.Time) (store.IdentitySnapshot, error) {
	result := store.IdentitySnapshot{IdentityScope: request.IdentityScope, SnapshotID: id, ObservedAt: request.ObservedAt.UTC(), IntervalSeconds: request.IntervalSeconds, Events: []normalized.Event{}}
	if request.Records == nil || !request.Complete || request.ExpectedCount == nil || *request.ExpectedCount != len(request.Records) || len(request.Records) > 10000 {
		return result, fmt.Errorf("complete inventory and matching expected_count (0..10000) required")
	}
	for _, value := range []string{id, request.Source, request.SensorID, request.CampusID, request.AccessDomain} {
		if strings.TrimSpace(value) == "" || len(value) > 200 || value != strings.TrimSpace(value) {
			return result, fmt.Errorf("explicit nonempty scope and snapshot ID required (maximum 200 characters)")
		}
	}
	if result.ObservedAt.IsZero() || result.ObservedAt.After(now) || result.ObservedAt.Before(now.Add(-7*24*time.Hour)) || result.ObservedAt.Nanosecond()%1000 != 0 {
		return result, fmt.Errorf("observed_at must be within the past seven days with at most microsecond precision")
	}
	if request.IntervalSeconds < 1 || request.IntervalSeconds > 86400 {
		return result, fmt.Errorf("reconcile_interval_seconds must be between 1 and 86400")
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

func (s *Server) handleIdentitySnapshot(w http.ResponseWriter, r *http.Request) {
	if s.identityIngest == nil || !s.identityIngest.authorized(r) {
		writeError(w, 401, "integration_auth_failed", "valid integration bearer token required")
		return
	}
	if s.readOnly {
		writeError(w, 403, "read_only", "identity ingestion disabled")
		return
	}
	backend, ok := s.reader.(store.IdentityReconciler)
	if !ok {
		writeError(w, 409, "identity_reconciliation_unavailable", "full reconciliation requires database storage")
		return
	}
	var request identitySnapshotRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, 400, "bad_identity_snapshot", err.Error())
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, 400, "bad_identity_snapshot", "exactly one JSON document required")
		return
	}
	snapshot, err := prepareIdentitySnapshot(request, r.Header.Get("Idempotency-Key"), time.Now().UTC())
	if err != nil {
		writeError(w, 400, "bad_identity_snapshot", err.Error())
		return
	}
	if err = s.validateIdentitySource(snapshot.IdentityScope, snapshot.IntervalSeconds); err != nil {
		writeError(w, 403, "identity_source_not_registered", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	created, err := backend.CommitIdentitySnapshot(ctx, snapshot)
	if errors.Is(err, store.ErrIdentitySnapshotConflict) {
		writeError(w, 409, "identity_snapshot_conflict", err.Error())
		return
	}
	if err != nil {
		writeError(w, 503, "identity_snapshot_commit_failed", err.Error())
		return
	}
	code := http.StatusAccepted
	if !created {
		code = http.StatusOK
	}
	writeJSON(w, code, map[string]any{"snapshot_id": snapshot.SnapshotID, "status": "completed", "observed_at": snapshot.ObservedAt, "session_count": len(snapshot.Events), "replayed": !created})
}
