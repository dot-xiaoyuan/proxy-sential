package controlplane

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
)

type idleSharedReader struct{ sharedTestReader }

func (idleSharedReader) ListPolicySessions(context.Context, time.Time) ([]policy.Session, error) {
	panic("idle shared review scanned policy identity history")
}

type idleProxyReader struct{ *proxyReplayReader }

func (idleProxyReader) ListPolicySessions(context.Context, time.Time) ([]policy.Session, error) {
	panic("empty proxy scan read policy identity history")
}

func TestIdleSharedReviewSkipsIdentityHistory(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.sharedConfig = sharedaccess.Config{Version: "test", FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "sensor", Source: "zeek", CampusID: "campus", AccessDomain: "domain"}}}
	s.reader = idleSharedReader{sharedTestReader{policySandboxReader: policySandboxReader{}, windows: nil}}
	s.sharedReviews.Position = 3
	s.materializeSharedReviews()
	if s.sharedReviews.Position != 0 {
		t.Fatal("idle review cursor was not reset")
	}
}

func TestEmptyProxyScanSkipsIdentityHistory(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.proxyConfig.Version = "test"
	s.reader = idleProxyReader{&proxyReplayReader{Reader: s.reader}}
	more, err := s.processProxyProtocol(context.Background(), time.Now().UTC())
	if err != nil || more {
		t.Fatalf("empty proxy scan failed: more=%v err=%v", more, err)
	}
}

func TestIdleAccountPoliciesSkipIdentityHistory(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.operations.db = db
	s.reader = idleSharedReader{sharedTestReader{policySandboxReader: policySandboxReader{}}}
	mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM account_policy_definitions").WithArgs(sharedaccess.ObservationPolicyID).WillReturnRows(sqlmock.NewRows([]string{"has_work"}).AddRow(false))
	s.processAccountPolicies(time.Now().UTC())
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
