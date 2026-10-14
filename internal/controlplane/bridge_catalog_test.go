package controlplane

import (
	"context"
	"database/sql"
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

// A configured bridge whose runtime version is still 0 — no identity snapshot
// has completed yet — must still resolve to the bridge source. Falling through
// to the placeholder source in that state left both scope selectors empty.
func TestFourKDirectorySourcePrefersConfiguredBridgeOverPlaceholder(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}, identityBridge: IdentityBridgeDefaults{}}
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS(SELECT 1 FROM identity_bridge_configs WHERE bridge_id=$1) OR EXISTS(SELECT 1 FROM identity_bridge_runtime WHERE bridge_id=$1 AND active_host<>'')`)).
		WithArgs(ncuIdentityBridgeID).
		WillReturnRows(sqlmock.NewRows([]string{"configured"}).AddRow(true))
	source, err := s.fourKDirectorySource(context.Background())
	if err != nil || source != "ncu-srun4k" {
		t.Fatalf("source=%q err=%v", source, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Only a site with neither a bridge nor a 4K integration falls back to the
// placeholder source, and that state must be reportable rather than silent.
func TestFourKDirectorySourceFallsBackOnlyWhenNothingIsConfigured(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(ncuIdentityBridgeID).
		WillReturnRows(sqlmock.NewRows([]string{"configured"}).AddRow(false))
	mock.ExpectQuery(`SELECT source FROM srun4k_integrations ORDER BY updated_at DESC LIMIT 1`).
		WillReturnError(sql.ErrNoRows)
	source, err := s.fourKDirectorySource(context.Background())
	if err != nil || source != defaultFourKSource {
		t.Fatalf("source=%q err=%v", source, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// An empty selector must name the source it looked at.
func TestDirectoryWarningsNameTheResolvedSource(t *testing.T) {
	warnings := directoryWarnings(fourKDirectory{Source: "ncu-srun4k"})
	if len(warnings) != 2 {
		t.Fatalf("warnings=%v", warnings)
	}
	for _, warning := range warnings {
		if !strings.Contains(warning, "ncu-srun4k") {
			t.Fatalf("warning does not name the source: %q", warning)
		}
	}
}

// Reproduces the production failure: the bridge is configured and its products
// and identity-observed groups exist under the bridge source, but the runtime
// version is still 0 because no identity snapshot has completed. The directory
// must still return both lists instead of resolving to an empty placeholder.
func TestFourKDirectoryReturnsCatalogWhileBridgeVersionIsZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}, identityBridge: IdentityBridgeDefaults{}}
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(ncuIdentityBridgeID).
		WillReturnRows(sqlmock.NewRows([]string{"configured"}).AddRow(true))
	source, err := s.fourKDirectorySource(context.Background())
	if err != nil || source != "ncu-srun4k" {
		t.Fatalf("source=%q err=%v", source, err)
	}
	// With active_config_version = 0 the handler scopes the directory without a
	// snapshot prefix and without the managed group key.
	mock.ExpectQuery(`SELECT product_id,name FROM product_catalog`).
		WithArgs("ncu-srun4k", "").
		WillReturnRows(sqlmock.NewRows([]string{"product_id", "name"}).
			AddRow("3", "教职工").
			AddRow("12", "学生包月40"))
	mock.ExpectQuery(`SELECT observed_at,\(SELECT count\(\*\) FROM product_control_catalog`).
		WithArgs("ncu-srun4k", "").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT observed_at,session_count FROM identity_full_snapshots`)).
		WithArgs("ncu-srun4k").
		WillReturnRows(sqlmock.NewRows([]string{"observed_at", "session_count"}).AddRow(time.Now().UTC(), 24932))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT group_id,name,parent_id,path FROM srun4k_group_catalog WHERE active AND source IN ($1,$2,$3) ORDER BY group_id`)).
		WithArgs("ncu-srun4k:identity-observed", "ncu-srun4k", "ncu-srun4k").
		WillReturnRows(sqlmock.NewRows([]string{"group_id", "name", "parent_id", "path"}).AddRow("208", "", "", ""))

	directory, err := loadFourKDirectoryWithGroupSource(context.Background(), db, source, "", source)
	if err != nil {
		t.Fatalf("directory failed: %v", err)
	}
	if len(directory.Products) != 2 || len(directory.Groups) != 1 {
		t.Fatalf("directory returned products=%d groups=%d", len(directory.Products), len(directory.Groups))
	}
	if len(directoryWarnings(directory)) != 0 {
		t.Fatalf("populated directory still warns: %v", directoryWarnings(directory))
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
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
