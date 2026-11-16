package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/identityprotocol"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

type identityDiagnosticReader struct {
	store.Reader
	lookupErr error
	acceptErr error
}

func (r identityDiagnosticReader) LookupIdentityReceipt(context.Context, string, string, int) (identityprotocol.Receipt, bool, error) {
	return identityprotocol.Receipt{}, false, r.lookupErr
}

func (r identityDiagnosticReader) AcceptIdentityBatch(context.Context, string, string, store.IdentityScope, []normalized.Event, int) (identityprotocol.Receipt, error) {
	return identityprotocol.Receipt{}, r.acceptErr
}

func TestDurableIdentityFailureDiagnosticPreservesHTTPResponse(t *testing.T) {
	scope := store.IdentityScope{Source: "radius", SensorID: "sensor-a", CampusID: "east", AccessDomain: "wifi"}
	request := identityprotocol.Request{Source: scope.Source, SensorID: scope.SensorID, Records: []map[string]string{{
		"entity_role": "endpoint", "account_id": "private-account", "session_id": "private-session",
		"ip": "192.0.2.1", "campus_id": scope.CampusID, "access_domain": scope.AccessDomain,
		"action": "login", "timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}}}
	for _, tc := range []struct {
		name, retry string
		reader      identityDiagnosticReader
	}{
		{"lookup", "", identityDiagnosticReader{lookupErr: errors.New("private lookup detail")}},
		{"accept", "2", identityDiagnosticReader{acceptErr: errors.New("private accept detail")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{reader: tc.reader, identityIngest: &identityIngestState{key: "test-token"},
				identitySources: []identitySourceRegistration{{IdentityScope: scope, IntervalSeconds: 60}}}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/identity/event-batches", bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer test-token")
			r.Header.Set("Idempotency-Key", "private-batch-id")
			w := httptest.NewRecorder()
			s.handleDurableIdentityBatch(w, r)
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != tc.retry ||
				!strings.Contains(w.Body.String(), "identity_inbox_unavailable") || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("failure response changed: status=%d retry=%q body=%s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
			}
		})
	}
}

type identityDiagnosticSQLState string

func (e identityDiagnosticSQLState) Error() string    { return "private database detail" }
func (e identityDiagnosticSQLState) SQLState() string { return string(e) }

func TestIdentityInboxFailureDiagnosticIsBoundedAndRedacted(t *testing.T) {
	var limiter apiSlowLogLimiter
	var lines []string
	emit := func(line string) { lines = append(lines, line) }
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	err := fmt.Errorf("private account and token: %w", identityDiagnosticSQLState("57014"))
	for range 5 {
		observeIdentityInboxFailure(&limiter, now, "lookup", 5*time.Second, err, emit)
	}
	if len(lines) != 2 {
		t.Fatalf("unbounded lookup diagnostics: %d", len(lines))
	}
	observeIdentityInboxFailure(&limiter, now, "accept", time.Second, context.DeadlineExceeded, emit)
	if len(lines) != 3 || !strings.Contains(lines[0], "stage=lookup") || !strings.Contains(lines[0], "sqlstate=57014") ||
		!strings.Contains(lines[2], "stage=accept") || !strings.Contains(lines[2], "deadline=true") {
		t.Fatalf("missing classified diagnostics: %q", lines)
	}
	for _, line := range lines {
		if strings.Contains(line, "private") || strings.Contains(line, "token") || strings.Contains(line, "account") {
			t.Fatalf("sensitive value leaked: %q", line)
		}
	}
	observeIdentityInboxFailure(&limiter, now.Add(slowAPILogWindow), "lookup", time.Second, err, emit)
	if len(lines) != 4 {
		t.Fatal("diagnostic bucket did not reopen")
	}
}
