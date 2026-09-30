package controlplane

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/evaluation"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
	"testing"
)

func historicalSampleFixture(t *testing.T) (*Server, evaluation.Sample, string) {
	t.Helper()
	dir := t.TempDir()
	date := "2026-09-30"
	sample := evaluation.Sample{Date: date, IP: "10.0.0.1", SubjectType: "ip", SubjectID: "10.0.0.1", SourceRunID: "run-1", SnapshotTime: date + "T12:00:00Z", EvidenceIDs: []string{"old", "missing"}}
	sample.SampleID = evaluation.SampleID(sample)
	for _, sub := range []string{"runs/run-1", "review-exports"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteJSON(t, filepath.Join(dir, "review-exports", date+"-review-samples.json"), map[string]any{"date": date, "samples": []evaluation.Sample{sample}})
	mustWriteJSON(t, filepath.Join(dir, "runs/run-1/risk-snapshots.json"), risk.BatchResult{Snapshots: []risk.Snapshot{{IP: sample.IP, SubjectType: sample.SubjectType, SubjectID: sample.SubjectID, UpdatedAt: sample.SnapshotTime, EvidenceIDs: sample.EvidenceIDs}}})
	mustWriteJSON(t, filepath.Join(dir, "runs/run-1/evidence.json"), evidence.Result{Evidence: []evidence.Evidence{{EvidenceID: "old", IP: sample.IP, Reason: "历史依据"}, {EvidenceID: "unrelated", IP: sample.IP}}})
	return NewServer(Options{ShadowDir: dir, ReadOnly: true}), sample, dir
}

func TestHistoricalSampleDetailIsBoundToOriginalEvidence(t *testing.T) {
	server, sample, dir := historicalSampleFixture(t)
	var result ShadowSampleDetail
	getJSON(t, server, "/api/v1/shadow/review-samples/"+sample.SampleID+"?date="+sample.Date, http.StatusOK, &result)
	if len(result.Evidence) != 1 || result.Evidence[0].EvidenceID != "old" || len(result.MissingEvidenceIDs) != 1 || result.MissingEvidenceIDs[0] != "missing" {
		t.Fatalf("wrong historical evidence: %+v", result)
	}
	var failure ErrorResponse
	getJSON(t, server, "/api/v1/shadow/review-samples/"+sample.SampleID+"?date=../../etc/passwd", http.StatusBadRequest, &failure)
	getJSON(t, server, "/api/v1/shadow/review-samples/sample-other?date="+sample.Date, http.StatusNotFound, &failure)
	if err := os.Remove(filepath.Join(dir, "runs/run-1/evidence.json")); err != nil {
		t.Fatal(err)
	}
	getJSON(t, server, "/api/v1/shadow/review-samples/"+sample.SampleID+"?date="+sample.Date, http.StatusNotFound, &failure)
}

func TestHistoricalSampleRejectsEscapingRunAndSymlink(t *testing.T) {
	server, sample, dir := historicalSampleFixture(t)
	outside := t.TempDir()
	mustWriteJSON(t, filepath.Join(outside, "proof.json"), evidence.Result{})
	if err := os.Remove(filepath.Join(dir, "runs/run-1/evidence.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "proof.json"), filepath.Join(dir, "runs/run-1/evidence.json")); err != nil {
		t.Fatal(err)
	}
	var failure ErrorResponse
	getJSON(t, server, "/api/v1/shadow/review-samples/"+sample.SampleID+"?date="+sample.Date, http.StatusInternalServerError, &failure)
	sample.SourceRunID = "../../outside"
	sample.SampleID = evaluation.SampleID(sample)
	mustWriteJSON(t, filepath.Join(dir, "review-exports", sample.Date+"-review-samples.json"), map[string]any{"samples": []evaluation.Sample{sample}})
	getJSON(t, server, "/api/v1/shadow/review-samples/"+sample.SampleID+"?date="+sample.Date, http.StatusInternalServerError, &failure)
}

func TestRuleCapabilityAndMenuReadPermissions(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	var status struct {
		Supported bool   `json:"reload_supported"`
		Status    string `json:"reload_status"`
	}
	getJSON(t, server, "/api/v1/rules/status", http.StatusOK, &status)
	if status.Supported || status.Status != "disabled" {
		t.Fatalf("false rule capability: %+v", status)
	}
	for path, want := range map[string]string{"/rules/status": "risks:read", "/campus-exceptions": "risks:read", "/shadow/review-samples/sample-a": "shadow:read"} {
		if got := requiredPermission(http.MethodGet, path); got != want {
			t.Fatalf("%s permission %s != %s", path, got, want)
		}
	}
	if requiredPermission(http.MethodPost, "/campus-exceptions") != "rules:reload" {
		t.Fatal("exception write permission changed")
	}
}

func TestHistoricalSampleReviewRejectsMissingProofAndAllowsDataRequest(t *testing.T) {
	server, sample, dir := historicalSampleFixture(t)
	server.readOnly = false
	submit := func(kind string, ids []string, status int) {
		t.Helper()
		body, err := json.Marshal(CreateLabelRequest{TargetType: "risk_snapshot", TargetID: sample.SampleID, SampleDate: sample.Date, Label: kind, Reason: "历史证据复核", EvidenceIDs: ids})
		if err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		postJSONBody(t, server, "/api/v1/labels", status, &response, string(body))
	}
	submit("confirmed_proxy", sample.EvidenceIDs, http.StatusConflict)
	submit("needs_more_data", []string{"unrelated"}, http.StatusConflict)
	submit("needs_more_data", sample.EvidenceIDs, http.StatusCreated)
	if err := os.Remove(filepath.Join(dir, "runs/run-1/evidence.json")); err != nil {
		t.Fatal(err)
	}
	submit("confirmed_proxy", sample.EvidenceIDs, http.StatusConflict)
	submit("needs_more_data", sample.EvidenceIDs, http.StatusCreated)
	submit("needs_more_data", []string{"unrelated"}, http.StatusConflict)
}

func TestStableSampleReviewListAndReplayUseSameMatching(t *testing.T) {
	server, sample, dir := historicalSampleFixture(t)
	second := sample
	second.SubjectID = "10.0.0.2"
	second.IP = second.SubjectID
	second.EvidenceIDs = []string{"other"}
	second.SampleID = evaluation.SampleID(second)
	mustWriteJSON(t, filepath.Join(dir, "runs/run-1/risk-snapshots.json"), risk.BatchResult{Snapshots: []risk.Snapshot{
		{IP: sample.IP, SubjectType: "ip", SubjectID: sample.SubjectID, UpdatedAt: sample.SnapshotTime, EvidenceIDs: sample.EvidenceIDs},
		{IP: second.IP, SubjectType: "ip", SubjectID: second.SubjectID, UpdatedAt: second.SnapshotTime, EvidenceIDs: second.EvidenceIDs},
	}})
	mustWriteJSON(t, filepath.Join(dir, "review-exports", sample.Date+"-review-samples.json"), map[string]any{"samples": []evaluation.Sample{sample, second}})
	label := store.Label{LabelID: "label-old", TargetType: "risk_snapshot", TargetID: sample.SourceRunID, Label: "benign", EvidenceIDs: sample.EvidenceIDs, CreatedAt: sample.SnapshotTime}
	data, _ := json.Marshal(label)
	if err := os.WriteFile(filepath.Join(dir, "labels.jsonl"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Samples []evaluation.Sample `json:"samples"`
	}
	getJSON(t, server, "/api/v1/shadow/review-samples?date="+sample.Date, http.StatusOK, &result)
	if len(result.Samples) != 2 {
		t.Fatalf("wrong samples: %+v", result)
	}
	for index, target := range []evaluation.Sample{sample, second} {
		evaluation.ApplySampleReview(&target, []evaluation.Sample{sample, second}, []store.Label{label})
		if result.Samples[index].SampleID != target.SampleID || result.Samples[index].ReviewStatus != target.ReviewStatus {
			t.Fatalf("live/offline disagreement: %+v / %+v", result.Samples[index], target)
		}
	}
}

func TestHistoricalSampleRejectsSnapshotProofMismatchAndReadError(t *testing.T) {
	server, sample, dir := historicalSampleFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "runs/run-1/evidence.json"), []byte("invalid JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	var response ErrorResponse
	getJSON(t, server, "/api/v1/shadow/review-samples/"+sample.SampleID+"?date="+sample.Date, http.StatusInternalServerError, &response)
	mustWriteJSON(t, filepath.Join(dir, "runs/run-1/risk-snapshots.json"), risk.BatchResult{Snapshots: []risk.Snapshot{{IP: sample.IP, SubjectType: sample.SubjectType, SubjectID: sample.SubjectID, UpdatedAt: sample.SnapshotTime, EvidenceIDs: []string{"unrelated"}}}})
	getJSON(t, server, "/api/v1/shadow/review-samples/"+sample.SampleID+"?date="+sample.Date, http.StatusInternalServerError, &response)
}
