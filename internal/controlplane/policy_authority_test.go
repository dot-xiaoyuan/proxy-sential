package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
)

func expectPolicyAuthorityManaged(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT i.connector_id,i.config_version`).WillReturnRows(sqlmock.NewRows([]string{"connector_id", "config_version", "public_config", "encrypted_token", "endpoint_url", "certificate_pem", "state", "blocker", "observed_at", "last_success_at", "last_attempt_at", "record_count"}))
}

func TestPolicyAuthorityCancellationReturnsNoTrustedSessions(t *testing.T) {
	now := time.Now().UTC()
	scope := store.IdentityScope{Source: "radius", SensorID: "one", CampusID: "east", AccessDomain: "wifi"}
	s := &Server{identitySources: []identitySourceRegistration{{IdentityScope: scope, IntervalSeconds: 60}}}
	reader := policySandboxReader{sessions: []policy.Session{{ID: "old", AccountID: "fixture", Source: scope.Source, SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, ConfirmedAt: now}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := s.policySessions(ctx, reader, now)
	if !errors.Is(err, context.Canceled) || len(got) != 0 {
		t.Fatalf("cancelled policy returned trusted sessions: rows=%d err=%v", len(got), err)
	}
	statuses, err := s.mergeManagedIdentitySources(ctx, []store.IdentitySourceStatus{{IdentityScope: scope, ObservedAt: now}}, now)
	if !errors.Is(err, context.Canceled) || len(statuses) != 0 {
		t.Fatalf("cancelled status returned success: rows=%d err=%v", len(statuses), err)
	}
}

func TestPolicyAuthorityFailureStopsApprovalAndDoesNotLeak(t *testing.T) {
	for _, query := range []string{"managed", "dynamic"} {
		t.Run(query, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			private := errors.New("private-authority-driver-detail")
			if query == "managed" {
				mock.ExpectQuery(`SELECT i.connector_id,i.config_version`).WillReturnError(private)
			} else {
				expectPolicyAuthorityManaged(mock)
				mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WillReturnError(private)
			}
			reader := policySandboxReader{sessions: []policy.Session{{ID: "old", AccountID: "fixture", Source: "srun4k:one", SensorID: "one", ConfirmedAt: time.Now().UTC()}}}
			s := &Server{operations: &operationsState{db: db}, reader: reader}
			got, err := s.policySessions(context.Background(), reader, time.Now().UTC())
			if err == nil || len(got) != 0 || !errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) {
				t.Fatalf("authority failure hidden/leaked: rows=%d err=%v", len(got), err)
			}
			if query == "managed" {
				mock.ExpectQuery(`SELECT i.connector_id,i.config_version`).WillReturnError(private)
			} else {
				expectPolicyAuthorityManaged(mock)
				mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WillReturnError(private)
			}
			w := httptest.NewRecorder()
			s.handlePolicyApprovalPreview(w, httptest.NewRequest(http.MethodGet, "/approval-preview", nil), "owned-fixture")
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), private.Error()) {
				t.Fatalf("approval continued/leaked: %d %s", w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPolicyAuthorityCancellationDuringSQLReturnsNoPartialSessions(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	expectPolicyAuthorityManaged(mock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WithArgs(cancelAuthorityArgument{value: "srun4k:one", cancel: cancel}, "one").WillReturnRows(sqlmock.NewRows([]string{"interval"}).AddRow(21600))
	reader := policySandboxReader{sessions: []policy.Session{{Source: "srun4k:one", SensorID: "one"}}}
	s := &Server{operations: &operationsState{db: db}}
	got, err := s.policySessions(ctx, reader, time.Now().UTC())
	if !errors.Is(err, context.Canceled) || len(got) != 0 {
		t.Fatalf("cancelled SQL returned success: rows=%d err=%v", len(got), err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyAuthorityScopeFilteringPreservesReader(t *testing.T) {
	reader := policySandboxReader{sessions: []policy.Session{{ID: "other", CampusID: "west", AccessDomain: "wifi"}, {ID: "selected", CampusID: "east", AccessDomain: "wifi"}}}
	s := &Server{}
	got, err := s.policySessionsForScope(context.Background(), reader, time.Now().UTC(), "east", "wifi")
	if err != nil || len(got) != 1 || got[0].ID != "selected" {
		t.Fatal(got, err)
	}
	if reader.sessions[0].ID != "other" {
		t.Fatal("scope filtering overwrote reader inventory")
	}
}
