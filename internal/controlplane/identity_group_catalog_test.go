package controlplane

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

func TestIdentityGroupCatalogSourceIsNamespaced(t *testing.T) {
	if got := identityGroupCatalogSource("ncu-srun4k"); got != "ncu-srun4k:identity-observed" {
		t.Fatalf("source=%q", got)
	}
	if got := identityGroupCatalogSource(""); got != "" {
		t.Fatalf("empty source produced %q", got)
	}
	// The identity key must never collide with the managed northbound key, or an
	// id-only observation could deactivate a named catalog.
	if identityGroupCatalogSource("ncu-srun4k") == managedGroupCatalogSource("ncu-srun4k", 4) {
		t.Fatal("identity group key collides with the managed bridge key")
	}
}

// An observation with no group must not touch the directory at all.
func TestRefreshIdentityGroupCatalogSkipsEmptyObservation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	snapshot := store.IdentitySnapshot{
		IdentityScope: store.IdentityScope{Source: "ncu-srun4k"},
		ObservedAt:    time.Now().UTC(),
		Events:        []normalized.Event{{Subject: map[string]any{"account_id": "acct"}}},
	}
	if err = s.refreshIdentityGroupCatalog(context.Background(), snapshot); err != nil {
		t.Fatalf("empty observation returned %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("empty observation touched the database: %v", err)
	}
}

func TestRefreshIdentityGroupCatalogWritesObservedGroups(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	observedAt := time.Date(2026, 10, 14, 2, 39, 41, 0, time.UTC)
	snapshot := store.IdentitySnapshot{
		IdentityScope: store.IdentityScope{Source: "ncu-srun4k"},
		ObservedAt:    observedAt,
		Events: []normalized.Event{
			{Subject: map[string]any{"account_id": "a"}, Payload: map[string]any{"group_id": "20"}},
			{Subject: map[string]any{"account_id": "b"}, Payload: map[string]any{"group_id": "10"}},
			{Subject: map[string]any{"account_id": "c"}, Payload: map[string]any{"group_id": "10"}},
		},
	}
	key := identityGroupCatalogSource("ncu-srun4k")
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE srun4k_group_catalog SET active=false,updated_at=now() WHERE source=$1`)).
		WithArgs(key).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO srun4k_group_catalog(source,group_id,name,parent_id,path,active,observed_at) VALUES($1,$2,$3,'','',true,$4) ON CONFLICT(source,group_id) DO UPDATE SET`)).
		WithArgs(key, "10", "", observedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO srun4k_group_catalog(source,group_id,name,parent_id,path,active,observed_at) VALUES($1,$2,$3,'','',true,$4) ON CONFLICT(source,group_id) DO UPDATE SET`)).
		WithArgs(key, "20", "", observedAt).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,'identity-bridge','integration.identity.groups',$2,$3,now())`)).
		WithArgs(sqlmock.AnyArg(), key, "observed:2").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err = s.refreshIdentityGroupCatalog(context.Background(), snapshot); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A snapshot without a source cannot be namespaced and must be ignored.
func TestRefreshIdentityGroupCatalogRequiresSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	snapshot := store.IdentitySnapshot{
		ObservedAt: time.Now().UTC(),
		Events:     []normalized.Event{{Payload: map[string]any{"group_id": "10"}}},
	}
	if err = s.refreshIdentityGroupCatalog(context.Background(), snapshot); err != nil {
		t.Fatalf("sourceless snapshot returned %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sourceless snapshot touched the database: %v", err)
	}
}

// The bounded selector read must surface an empty directory instead of leaving
// the operator with an unexplained blank list.
func TestDirectoryWarningsExplainEmptySelectors(t *testing.T) {
	warnings := directoryWarnings(fourKDirectory{})
	if len(warnings) != 2 {
		t.Fatalf("warnings=%v", warnings)
	}
	full := directoryWarnings(fourKDirectory{
		Products: []fourKDirectoryItem{{ID: "3"}},
		Groups:   []fourKDirectoryItem{{ID: "12"}},
	})
	if len(full) != 0 {
		t.Fatalf("populated directory produced warnings: %v", full)
	}
}
