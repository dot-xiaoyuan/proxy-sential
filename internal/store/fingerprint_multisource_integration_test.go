package store

import (
	"context"
	"encoding/json"
	"os"
	"proxy-sentinel/internal/fingerprint"
	"testing"
	"time"
)

func TestFingerprintCoverageAndRebuildLanesPostgres(t *testing.T) {
	s := recognitionLeasePrivatePostgres(t)
	ctx := context.Background()
	for _, name := range []string{"100_recognition_queue_coalescing.sql", "101_fingerprint_rebuild_lane.sql"} {
		data, e := os.ReadFile("../../migrations/postgres/" + name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.pg.db.Exec(string(data)); e != nil {
			t.Fatal(e)
		}
	}
	_, err := s.pg.db.Exec(`ALTER TABLE endpoint_entities ADD entity_role text DEFAULT 'endpoint',ADD last_seen timestamptz DEFAULT now(),ADD attributes jsonb DEFAULT '{"server":"Printer"}'; INSERT INTO endpoint_recognition_summary(endpoint_id,last_seen,summary) VALUES('endpoint',now(),'{"source_matches":[{"source_id":"recog","rule_id":"a"},{"source_id":"satori","rule_id":"b"}]}')`)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.refreshFingerprintCoverage(ctx); err != nil {
		t.Fatal(err)
	}
	out, err := s.FingerprintSourceCoverage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out["overlap_endpoints"] != float64(1) {
		t.Fatalf("coverage: %+v", out)
	}

	matches := []fingerprint.SourceMatch{{SourceID: "recog", RuleID: "a"}}
	s.fingerprintMatches.record(time.Now(), false, matches)
	s.fingerprintMatches.record(time.Now(), true, matches)
	if err = s.flushFingerprintMatchCounts(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.flushFingerprintMatchCounts(ctx); err != nil {
		t.Fatal(err)
	}
	out, err = s.FingerprintSourceCoverage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range out["items"].([]any) {
		item := value.(map[string]any)
		if item["source_id"] == "recog" && (item["evaluation_match_count"] != int64(2) || item["realtime_match_count"] != int64(1) || item["history_match_count"] != int64(1)) {
			t.Fatalf("bad evaluation counters: %+v", item)
		}
	}
	// Finish the existing live job, then a changed field enters the historical lane.
	job, found, err := s.claimRecognitionJob(ctx, "live-0")
	if err != nil || !found {
		t.Fatal("claim live", err)
	}
	if err = s.finishRecognitionJob(ctx, job, nil); err != nil {
		t.Fatal(err)
	}
	if err = s.enqueueFingerprintRebuild(ctx, "v1", map[string]string{"server": "h1"}); err != nil {
		t.Fatal(err)
	}
	if _, found, err = s.claimRecognitionJob(ctx, "live-0"); err != nil || found {
		t.Fatal("live consumed historical", err)
	}
	if _, found, err = s.claimRecognitionJob(ctx, "historical-3"); err != nil || !found {
		t.Fatal("historical lane not claimable", err)
	}
	if _, err = s.pg.db.Exec(`SELECT mark_endpoint_recognition_dirty('endpoint')`); err != nil {
		t.Fatal(err)
	}
	var lane int
	if err = s.pg.db.QueryRow(`SELECT lane FROM endpoint_recognition_jobs`).Scan(&lane); err != nil || lane != 0 {
		t.Fatal("live update did not promote task", err)
	}
	// A metadata-only version update must not requeue matching fields.
	if err = s.enqueueFingerprintRebuild(ctx, "v2", map[string]string{"server": "h1"}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err = s.pg.db.QueryRow(`SELECT state FROM read_model_runtime_state WHERE name='fingerprint-rebuild'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	_ = json.Unmarshal(raw, &state)
	if state["visited"] != float64(0) {
		t.Fatal("unchanged field requeued", state)
	}
	// Old statistics must not be presented as current coverage.
	if _, err = s.pg.db.Exec(`UPDATE read_model_runtime_state SET state=jsonb_set(state,'{as_of}',to_jsonb($1::text)) WHERE name='fingerprint-source-coverage'`, time.Now().Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	out, err = s.FingerprintSourceCoverage(ctx)
	if err != nil || out["status"] != "stale" {
		t.Fatal("stale coverage", out, err)
	}
}
