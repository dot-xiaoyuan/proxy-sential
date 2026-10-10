package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/productpolicy"
)

func bridgeCatalogFixture(host string, version int64) productpolicy.BridgeCatalogSnapshot {
	snapshot := productpolicy.Snapshot{SchemaVersion: productpolicy.SchemaVersion, Source: "ncu-srun4k", InstanceID: "catalog-redis", ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Complete: true, Products: []productpolicy.Product{{ID: "p1", Name: "测试产品"}}, Controls: []productpolicy.Control{}}
	_ = snapshot.NormalizeAndValidate(time.Now().UTC())
	return productpolicy.BridgeCatalogSnapshot{Host: host, ConfigVersion: version, Snapshot: snapshot}
}

func TestFourKDirectoryDefaultsToManagedIdentitySource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}, identityBridge: IdentityBridgeDefaults{}}
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(ncuIdentityBridgeID).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	source, err := s.fourKDirectorySource(context.Background())
	if err != nil || source != "ncu-srun4k" {
		t.Fatalf("source=%q err=%v", source, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFourKDirectorySourceQueryFailureDoesNotFallBack(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnError(errors.New("database unavailable"))
	if source, err := s.fourKDirectorySource(context.Background()); err == nil || source != "" {
		t.Fatalf("source=%q err=%v", source, err)
	}
}

func TestBridgeCatalogKeepsBearerAndReadOnlyAdmission(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.operations.db = db
	s.identityIngest.key = "bridge-token"
	for _, tc := range []struct {
		token string
		allow bool
		want  int
	}{
		{"", true, http.StatusUnauthorized},
		{"wrong-token", true, http.StatusUnauthorized},
		{"bridge-token", false, http.StatusForbidden},
		{"bridge-token", true, http.StatusBadRequest},
	} {
		s.allowIdentityIngest = tc.allow
		r := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/identity/bridge/catalog-snapshots", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+tc.token)
		r.Header.Set("Idempotency-Key", "catalog-test")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("response=%d %s want=%d", w.Code, w.Body.String(), tc.want)
		}
	}
	// The generic product ingestion route must remain disabled in read-only.
	s.productPolicies = &productPolicyState{key: "policy-token", db: db}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/product-policy/snapshots", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer policy-token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("generic ingest protection lost: %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeCatalogChecksCommittedHostUnderTransaction(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(bridgeCatalogScopeQuery)).WithArgs(ncuIdentityBridgeID).WillReturnRows(sqlmock.NewRows([]string{"active_host", "active_config_version", "last_snapshot_at"}).AddRow("222.204.3.224", 1, nil))
	mock.ExpectRollback()
	_, _, err := commitBridgeCatalogSnapshot(context.Background(), db, IdentityBridgeDefaults{}.normalized(), "catalog-test", bridgeCatalogFixture("222.204.3.225", 2))
	if !errors.Is(err, errBridgeCatalogScope) {
		t.Fatalf("pending address accepted: %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
