package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExportWindowUsesHalfOpenRange(t *testing.T) {
	from, to, err := exportWindow("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !withinExportWindow("2026-09-01T00:00:00Z", from, to) {
		t.Fatal("start should be included")
	}
	if withinExportWindow("2026-09-02T00:00:00Z", from, to) {
		t.Fatal("end should be excluded")
	}
	if _, _, err := exportWindow(to.Format(time.RFC3339), from.Format(time.RFC3339)); err == nil {
		t.Fatal("expected reversed range error")
	}
}

func TestSafeCSVCellNeutralizesSpreadsheetFormula(t *testing.T) {
	if got := safeCSVCell("=HYPERLINK(\"https://example.test\")"); got[0] != '\'' {
		t.Fatalf("formula was not neutralized: %q", got)
	}
	if got := safeCSVCell("normal"); got != "normal" {
		t.Fatalf("normal value changed: %q", got)
	}
}

func TestExportEndpointGeneratesDownloadAsynchronously(t *testing.T) {
	dir := t.TempDir()
	server := NewServer(Options{ShadowDir: dir, ExportDir: dir + "/exports"})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/exports", bytes.NewBufferString(`{"kind":"risks"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var job ExportJob
	if err := json.Unmarshal(response.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, _ = server.exports.get(job.ExportID)
		if job.Status == "completed" || job.Status == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if job.Status != "completed" {
		t.Fatalf("export did not complete: %+v", job)
	}
	download := httptest.NewRecorder()
	server.Handler().ServeHTTP(download, httptest.NewRequest(http.MethodGet, "/api/v1/exports/"+job.ExportID+"/download", nil))
	if download.Code != http.StatusOK || download.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatalf("download status=%d headers=%v", download.Code, download.Header())
	}
}
