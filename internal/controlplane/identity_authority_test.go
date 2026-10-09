package controlplane

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

type cancelAuthorityArgument struct {
	value  string
	cancel context.CancelFunc
}

func (m cancelAuthorityArgument) Match(value driver.Value) bool {
	if value != m.value {
		return false
	}
	m.cancel()
	return true
}

func TestIdentityAuthorityCancellationPreventsStaticTrust(t *testing.T) {
	scope := store.IdentityScope{Source: "radius", SensorID: "sensor", CampusID: "east", AccessDomain: "wifi"}
	s := &Server{identitySources: []identitySourceRegistration{{IdentityScope: scope, IntervalSeconds: 60}}}
	for _, cause := range []string{"cancelled", "deadline"} {
		t.Run(cause, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			expected := context.Canceled
			if cause == "cancelled" {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				expected = context.DeadlineExceeded
			}
			defer cancel()
			if err := s.validateIdentitySourceContext(ctx, scope, 60); !errors.Is(err, expected) {
				t.Fatalf("cancelled authority accepted: %v", err)
			}
			event := normalized.Event{Source: scope.Source, Observer: map[string]any{"sensor_id": scope.SensorID}, Subject: map[string]any{"campus_id": scope.CampusID}, Payload: map[string]any{"access_domain": scope.AccessDomain, "reconcile_interval_seconds": 999}}
			if err := s.applyIdentityRegistrationContext(ctx, &event); !errors.Is(err, expected) || event.Payload["reconcile_interval_seconds"] != 999 {
				t.Fatalf("cancelled registration mutated event: %v %+v", err, event.Payload)
			}
		})
	}
}

func TestIdentityAuthorityCancellationDuringQueryRetainsCause(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WithArgs(cancelAuthorityArgument{value: "srun4k:one", cancel: cancel}, "one").WillReturnRows(sqlmock.NewRows([]string{"interval"}).AddRow(21600))
	err = s.validateIdentitySourceContext(ctx, store.IdentityScope{Source: "srun4k:one", SensorID: "one"}, 21600)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost query cancellation: %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func authorityBatchRequest(records int) identityIngestRequest {
	request := identityIngestRequest{Source: "srun4k:one", SensorID: "one", Records: make([]map[string]string, records)}
	for i := range request.Records {
		request.Records[i] = map[string]string{"account_id": "fixture-account", "session_id": fmt.Sprint(i), "ip": "192.0.2.1", "timestamp": "2026-10-01T03:00:00Z", "reconcile_interval_seconds": "604800"}
	}
	return request
}
func runAuthorityBatch(t *testing.T, s *Server, request identityIngestRequest, id string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/identity/events", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Idempotency-Key", id)
	w := httptest.NewRecorder()
	s.handleIdentityIngest(w, req)
	return w
}

func TestIdentityAuthorityBatchResolvesOnceAndReloads(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &replayIdentityReader{}
	s := &Server{operations: &operationsState{db: db}, reader: reader, identityIngest: &identityIngestState{key: "token", batches: map[string]IdentityIngestBatch{}}}
	request := authorityBatchRequest(128)
	for i, interval := range []int{21600, 3600} {
		mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WithArgs("srun4k:one", "one").WillReturnRows(sqlmock.NewRows([]string{"interval"}).AddRow(interval))
		reader.events = nil
		w := runAuthorityBatch(t, s, request, fmt.Sprint(i))
		if w.Code != http.StatusAccepted || len(reader.events) != 128 {
			t.Fatalf("batch registration repeated/rejected: status=%d events=%d %s", w.Code, len(reader.events), w.Body.String())
		}
		for _, event := range reader.events {
			if event.Payload["reconcile_interval_seconds"] != interval || event.Payload["heartbeat_interval_seconds"] != interval {
				t.Fatal("sender/cached interval overrode fresh authority")
			}
		}
		if err = mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIdentityAuthorityLookupFailureIsUnavailable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &replayIdentityReader{}
	s := &Server{operations: &operationsState{db: db}, reader: reader, identityIngest: &identityIngestState{key: "token", batches: map[string]IdentityIngestBatch{}}}
	mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WillReturnError(errors.New("private-driver-detail"))
	w := runAuthorityBatch(t, s, authorityBatchRequest(1), "unavailable")
	if w.Code != http.StatusServiceUnavailable || len(reader.events) != 0 || strings.Contains(w.Body.String(), "private-driver-detail") {
		t.Fatalf("DB failure mislabeled/leaked: %d %s", w.Code, w.Body.String())
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityAuthorityCachedScopeHonorsLaterCancellation(t *testing.T) {
	scope := store.IdentityScope{Source: "radius", SensorID: "sensor", CampusID: "east", AccessDomain: "wifi"}
	s := &Server{identitySources: []identitySourceRegistration{{IdentityScope: scope, IntervalSeconds: 60}}}
	resolver := newIdentityAuthorityResolver(s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := resolver.resolve(ctx, scope); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := resolver.resolve(ctx, scope); !errors.Is(err, context.Canceled) {
		t.Fatalf("cached authority ignored cancellation: %v", err)
	}
}

func TestIdentityAuthoritySnapshotCancellationDuringQueryDoesNotCommit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &snapshotReader{}
	s := &Server{operations: &operationsState{db: db}, reader: reader, identityIngest: &identityIngestState{key: "token"}}
	count := 0
	request := identitySnapshotRequest{IdentityScope: store.IdentityScope{Source: "srun4k:one", SensorID: "one"}, ObservedAt: time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute), IntervalSeconds: 21600, Complete: true, ExpectedCount: &count, Records: []map[string]string{}}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/identity/snapshot", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Idempotency-Key", "cancelled-authority")
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WithArgs(cancelAuthorityArgument{value: "srun4k:one", cancel: cancel}, "one").WillReturnRows(sqlmock.NewRows([]string{"interval"}).AddRow(21600))
	w := httptest.NewRecorder()
	s.handleIdentitySnapshot(w, req.WithContext(ctx))
	if w.Code != http.StatusRequestTimeout || reader.commits != 0 {
		t.Fatalf("cancelled query reached snapshot commit: status=%d calls=%d", w.Code, reader.commits)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityAuthorityMixedBatchIsRejectedBeforeIngest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &replayIdentityReader{}
	s := &Server{operations: &operationsState{db: db}, reader: reader, identityIngest: &identityIngestState{key: "token", batches: map[string]IdentityIngestBatch{}}}
	request := authorityBatchRequest(2)
	request.Records[1]["campus_id"] = "foreign-campus"
	mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WithArgs("srun4k:one", "one").WillReturnRows(sqlmock.NewRows([]string{"interval"}).AddRow(21600))
	w := runAuthorityBatch(t, s, request, "mixed-authority")
	if w.Code != http.StatusForbidden || len(reader.events) != 0 || len(s.identityIngest.batches) != 0 {
		t.Fatalf("mixed batch partially ingested or persisted: status=%d events=%d batches=%d", w.Code, len(reader.events), len(s.identityIngest.batches))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
