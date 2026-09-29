package controlplane

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExportJobsRestartAndIdempotency(t *testing.T) {
	dir := t.TempDir()
	m, err := newExportManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	job := ExportJob{ExportID: "export-replay", Kind: "risks", Status: "queued", CreatedBy: "operator", CreatedAt: "2026-09-17T01:00:00Z", IdempotencyKey: "request-1"}
	if _, err = m.submit(job); err != nil {
		t.Fatal(err)
	}
	id, err := m.claim()
	if err != nil || id != job.ExportID {
		t.Fatalf("claim=%s err=%v", id, err)
	}
	if err = os.WriteFile(filepath.Join(dir, id+".csv.tmp"), []byte("incomplete output"), 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := newExportManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	actual, found := recovered.get(id)
	if !found || actual.Status != "queued" {
		t.Fatalf("not recovered: %+v", actual)
	}
	if _, err = os.Stat(filepath.Join(dir, id+".csv.tmp")); !os.IsNotExist(err) {
		t.Fatalf("partial output remains: %v", err)
	}
	job.ExportID = "export-repeated-request"
	actual, err = recovered.submit(job)
	if err != nil || actual.ExportID != id {
		t.Fatalf("duplicate task: %+v err=%v", actual, err)
	}
	job.Kind = "evidence"
	if _, err = recovered.submit(job); err == nil {
		t.Fatal("changed parameters accepted for the same key")
	}
	job.Kind, job.CreatedBy = "risks", "another-operator"
	if actual, err = recovered.submit(job); err != nil || actual.ExportID == id {
		t.Fatalf("owner isolation: %+v %v", actual, err)
	}
	first, err := recovered.claim()
	if err != nil || first == "" {
		t.Fatalf("claim: %s %v", first, err)
	}
	second, err := recovered.claim()
	if err != nil || second == "" || first == second {
		t.Fatalf("duplicate worker claim: %s %s %v", first, second, err)
	}
}

func TestExportSubmissionDoesNotSucceedWithoutPersistence(t *testing.T) {
	m, err := newExportManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m.dir = filepath.Join(m.dir, "missing", "directory")
	job := ExportJob{ExportID: "export-storage-failure", Kind: "risks", Status: "queued"}
	if _, err = m.submit(job); err == nil {
		t.Fatal("submission succeeded without persisted task")
	}
	if _, found := m.get(job.ExportID); found {
		t.Fatal("failed task is visible as accepted")
	}
}

func TestExportCancellationPersistsAndStopsRunningWorker(t *testing.T) {
	m, err := newExportManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	job := ExportJob{ExportID: "cancelled-export", Kind: "risks", Status: "queued"}
	if _, err = m.submit(job); err != nil {
		t.Fatal(err)
	}
	if _, err = m.claim(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	m.cancels[job.ExportID] = func() { stopped = true }
	if _, err = m.cancel(job.ExportID); err != nil || !stopped {
		t.Fatalf("cancel did not stop worker: %v", err)
	}
	recovered, err := newExportManager(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := recovered.get(job.ExportID)
	if actual.Status != "cancelled" {
		t.Fatalf("cancel was lost: %+v", actual)
	}
	if id, err := recovered.claim(); err != nil || id != "" {
		t.Fatalf("cancelled export executed: %s %v", id, err)
	}
	job.ExportID = "terminal-export"
	job.Status = "completed"
	if err = m.put(job); err != nil {
		t.Fatal(err)
	}
	if _, err = m.cancel(job.ExportID); err != errExportTerminal {
		t.Fatalf("terminal export cancel: %v", err)
	}
}
