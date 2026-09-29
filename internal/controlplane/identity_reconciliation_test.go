package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/store"
	"strings"
	"testing"
	"time"
)

type snapshotReader struct {
	store.Reader
	commits  int
	snapshot store.IdentitySnapshot
	err      error
}

func (r *snapshotReader) CommitIdentitySnapshot(_ context.Context, s store.IdentitySnapshot) (bool, error) {
	r.commits++
	r.snapshot = s
	return true, r.err
}
func (r *snapshotReader) IdentitySources(context.Context, time.Time) ([]store.IdentitySourceStatus, error) {
	return []store.IdentitySourceStatus{}, nil
}
func TestIdentitySnapshotValidationBeforeCommit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	one := 1
	valid := identitySnapshotRequest{IdentityScope: store.IdentityScope{Source: "radius", SensorID: "a", CampusID: "east", AccessDomain: "wifi"}, ObservedAt: now, IntervalSeconds: 60, Complete: true, ExpectedCount: &one, Records: []map[string]string{{"session_id": "s", "account_id": "alice", "ip": "192.0.2.1"}}}
	for _, name := range []string{"valid", "missing_records", "partial", "count", "scope", "invalid_ip", "duplicate", "future", "unauthorized", "readonly", "trailing_json"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(valid)
			var request identitySnapshotRequest
			json.Unmarshal(raw, &request)
			switch name {
			case "missing_records":
				request.Records = nil
				zero := 0
				request.ExpectedCount = &zero
			case "partial":
				request.Complete = false
			case "count":
				n := 2
				request.ExpectedCount = &n
			case "scope":
				request.Records[0]["campus_id"] = "west"
			case "invalid_ip":
				request.Records[0]["ip"] = "garbage"
			case "duplicate":
				request.Records = append(request.Records, request.Records[0])
				n := 2
				request.ExpectedCount = &n
			case "future":
				request.ObservedAt = time.Now().Add(time.Hour)
			}
			raw, _ = json.Marshal(request)
			if name == "trailing_json" {
				raw = append(raw, []byte(" {}")...)
			}
			reader := &snapshotReader{}
			server := &Server{identitySources: []identitySourceRegistration{{IdentityScope: valid.IdentityScope, IntervalSeconds: 60}}, reader: reader, identityIngest: &identityIngestState{key: "token"}, readOnly: name == "readonly"}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/identity/snapshots", bytes.NewReader(raw))
			req.Header.Set("Idempotency-Key", "snapshot-1")
			if name != "unauthorized" {
				req.Header.Set("Authorization", "Bearer token")
			}
			w := httptest.NewRecorder()
			server.handleIdentitySnapshot(w, req)
			if name == "valid" {
				if w.Code != 202 || reader.commits != 1 || len(reader.snapshot.Events) != 1 {
					t.Fatalf("valid rejected %d %s", w.Code, w.Body.String())
				}
			} else if w.Code < 400 || reader.commits != 0 {
				t.Fatalf("invalid inventory committed %d %s", w.Code, w.Body.String())
			}
		})
	}
	zero := 0
	valid.ExpectedCount = &zero
	valid.Records = []map[string]string{}
	snapshot, err := prepareIdentitySnapshot(valid, "empty", time.Now())
	if err != nil || len(snapshot.Events) != 0 {
		t.Fatalf("complete empty snapshot rejected: %v", err)
	}
}
func TestIdentityMetricsInterruptedSource(t *testing.T) {
	var out bytes.Buffer
	writeIdentityMetrics(&out, []store.IdentitySourceStatus{{IdentityScope: store.IdentityScope{Source: "radius", SensorID: "a", CampusID: "east", AccessDomain: "wifi"}, State: "interrupted", AgeSeconds: 180, SessionCount: 2}})
	if !strings.Contains(out.String(), "proxy_sentinel_identity_source_interrupted{source=\"radius\",sensor_id=\"a\",campus_id=\"east\",access_domain=\"wifi\"} 1") {
		t.Fatal(out.String())
	}
}
