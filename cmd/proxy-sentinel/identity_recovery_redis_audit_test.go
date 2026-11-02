package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdentityRedisAuditKeepsOnlyBoundaryHashAndTime(t *testing.T) {
	raw := `{"send_time":1793619650,"user_name":"sensitive-user","mobile_password":"sensitive-secret"}`
	summary, err := identityRedisRawSummary(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SHA256 == "" || summary.Bytes != len(raw) || summary.SendTime == "" ||
		strings.Contains(string(encoded), "sensitive-user") || strings.Contains(string(encoded), "sensitive-secret") {
		t.Fatalf("raw identity data escaped audit boundary: %s", encoded)
	}
}

func TestReadIdentityRedisAuditRequiresFreshProtectedMatchingLists(t *testing.T) {
	now := time.Now().UTC()
	hash := strings.Repeat("a", 64)
	audit := identityRedisAudit{
		Kind: "identity_redis_boundary_sample_v1", SampleStartedAt: now.Add(-time.Second), SampleCompletedAt: now,
		EventList: "source", ProcessingList: "processing",
		Source:     identityRedisListAudit{Length: 1, Head: &identityRedisRawBoundary{Bytes: 10, SHA256: hash}, Tail: &identityRedisRawBoundary{Bytes: 10, SHA256: hash}},
		Processing: identityRedisListAudit{}, Caveat: "boundary sample only",
	}
	write := func(value identityRedisAudit, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "audit.json")
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := write(audit, 0600)
	if digest, _, err := readIdentityRedisAudit(path, "source", "processing"); err != nil || len(digest) != 64 {
		t.Fatalf("valid audit rejected: %s %v", digest, err)
	}
	if _, _, err := readIdentityRedisAudit(path, "other", "processing"); err == nil {
		t.Fatal("wrong source list accepted")
	}
	if _, _, err := readIdentityRedisAudit(path, "source", "other"); err == nil {
		t.Fatal("wrong processing list accepted")
	}
	stale := audit
	stale.SampleStartedAt = now.Add(-time.Hour)
	stale.SampleCompletedAt = now.Add(-time.Hour)
	if _, _, err := readIdentityRedisAudit(write(stale, 0600), "source", "processing"); err == nil {
		t.Fatal("stale audit accepted")
	}
	if _, _, err := readIdentityRedisAudit(write(audit, 0644), "source", "processing"); err == nil {
		t.Fatal("unprotected audit accepted")
	}
}
