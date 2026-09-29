package appdomain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestScanWindowProgressAndRestart(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	j := Job{From: from, To: from.Add(time.Hour), Status: "running"}
	q := j.ScanWindow()
	if q.To.Sub(q.From) != 10*time.Minute {
		t.Fatal(q)
	}
	j.FinishScanWindow(q, 0)
	if j.Status != "running" {
		t.Fatal("empty slice completed entire job")
	}
	raw, _ := json.Marshal(j)
	var restart Job
	if err := json.Unmarshal(raw, &restart); err != nil {
		t.Fatal(err)
	}
	q = restart.ScanWindow()
	if !q.From.Equal(from.Add(10 * time.Minute)) {
		t.Fatal(q)
	}
	restart.After = Cursor{Timestamp: q.From.Format(time.RFC3339Nano), EventID: "5000"}
	restart.FinishScanWindow(q, applicationScanBatchSize)
	if next := restart.ScanWindow(); !next.From.Equal(q.From) || !next.To.Equal(q.To) || next.After.EventID != "5000" {
		t.Fatal(next)
	}
	for restart.Status == "running" {
		q = restart.ScanWindow()
		restart.FinishScanWindow(q, 0)
	}
	if !restart.ScanFrom.Equal(restart.To) {
		t.Fatal(restart)
	}
}

func TestScanWindowShrinkDoesNotAdvance(t *testing.T) {
	from := time.Now().UTC()
	j := Job{From: from, To: from.Add(time.Hour), After: Cursor{Timestamp: from.Add(3 * time.Minute).Format(time.RFC3339Nano)}}
	for i := 0; i < 20; i++ {
		j.ShrinkScanWindow()
	}
	q := j.ScanWindow()
	if q.To.Sub(q.From) != time.Second || !j.From.Equal(from) || j.After.Timestamp == "" {
		t.Fatal(q, j)
	}
	if j.ShrinkScanWindow() {
		t.Fatal("shrunk below minimum")
	}
}

func TestScanWindowShrinkUsesRemainingWidth(t *testing.T) {
	from := time.Now().UTC()
	j := Job{From: from, To: from.Add(20 * time.Second)}
	if !j.ShrinkScanWindow() || j.ScanWindow().To.Sub(j.ScanWindow().From) != 10*time.Second {
		t.Fatal(j)
	}
}
