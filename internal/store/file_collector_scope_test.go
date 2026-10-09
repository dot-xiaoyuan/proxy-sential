package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileCollectorSummaryPreservesSensorNamespace(t *testing.T) {
	root := t.TempDir()
	for _, r := range []struct{ name, sensor, at string }{{"local-run", "local", "2026-10-01T00:00:00Z"}, {"other-run", "other", "2026-10-01T01:00:00Z"}} {
		dir := filepath.Join(root, "runs", r.name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		data := `{"sensor_id":"` + r.sensor + `","started_at":"` + r.at + `","finished_at":"` + r.at + `","normalized":{"read":3,"by_type":{"dns":3}}}`
		if err := os.WriteFile(filepath.Join(dir, "run-summary.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := NewFileStore(FileOptions{ShadowDir: root, SensorID: "local"})
	status, err := s.IngestStatus(context.Background())
	if err != nil || status.LatestRunID != "local-run" {
		t.Fatalf("other summary relabeled as local: %+v %v", status, err)
	}
	all, err := s.ListRuns(context.Background(), 10)
	if err != nil || len(all) != 2 || all[0].SensorID != "other" {
		t.Fatalf("global run identity lost: %+v %v", all, err)
	}
}
