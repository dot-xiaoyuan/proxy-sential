package devicesignal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

func TestCaptureCoverageCheckpointUsesDurableTailAndAdjacentRotation(t *testing.T) {
	output := filepath.Join(t.TempDir(), "ttl.jsonl")
	start := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	first := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: start, To: start.Add(30 * time.Second), KernelStatsKnown: true}
	second := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: first.To, To: first.To.Add(30 * time.Second), KernelStatsKnown: true}
	if err := writeCaptureCoverage(output, "sensor", "bond0", "instance", "packet-sidecar", nil, first); err != nil {
		t.Fatal(err)
	}
	if err := saveCaptureCoverageCheckpoint(output, "sensor", "instance", first); err != nil {
		t.Fatal(err)
	}
	if err := writeCaptureCoverage(output, "sensor", "bond0", "instance", "packet-sidecar", nil, second); err != nil {
		t.Fatal(err)
	}
	got, found, err := lastPersistedCaptureCoverage(output, "sensor", "instance")
	if err != nil || !found || !got.To.Equal(second.To) {
		t.Fatalf("prefer synced output ahead of stale checkpoint: coverage=%+v found=%t err=%v", got, found, err)
	}
	if err := os.Rename(output, output+"-20261113-120100"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, nil, 0640); err != nil {
		t.Fatal(err)
	}
	got, found, err = lastPersistedCaptureCoverage(output, "sensor", "instance")
	if err != nil || !found || !got.To.Equal(second.To) {
		t.Fatalf("adjacent rotation: coverage=%+v found=%t err=%v", got, found, err)
	}
	gap, needed := captureCoverageGap(got, second.To.Add(time.Minute))
	if !needed || !gap.From.Equal(second.To) || !gap.To.Equal(second.To.Add(time.Minute)) || gap.KernelStatsKnown || !gap.Stopped || gap.Complete() {
		t.Fatalf("restart gap is not incomplete: %+v needed=%t", gap, needed)
	}
}

func TestCaptureCoverageCheckpointRejectsCorruptionAndPartialOutput(t *testing.T) {
	output := filepath.Join(t.TempDir(), "ttl.jsonl")
	coverage := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: time.Now().UTC().Add(-time.Minute), To: time.Now().UTC(), KernelStatsKnown: true}
	if err := saveCaptureCoverageCheckpoint(output, "sensor", "instance", coverage); err != nil {
		t.Fatal(err)
	}
	path := captureCoverageCheckpointPath(output)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw[:len(raw)-2], []byte("x\n")...), 0640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCaptureCoverageCheckpoint(output, "sensor", "instance"); err == nil {
		t.Fatal("corrupt checkpoint was accepted")
	}
	if err := os.WriteFile(output, []byte(`{"source_event_type":"capture_coverage"}`), 0640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lastPersistedCaptureCoverage(output, "sensor", "instance"); !errors.Is(err, errCaptureOutputIncomplete) {
		t.Fatalf("partial source record was not rejected: %v", err)
	}
}

func TestCaptureCoverageNumericRotationsPreferOneOverTwo(t *testing.T) {
	output := filepath.Join(t.TempDir(), "ttl.jsonl")
	start := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	old := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: start, To: start.Add(30 * time.Second), KernelStatsKnown: true}
	newer := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: old.To, To: old.To.Add(30 * time.Second), KernelStatsKnown: true}
	if err := writeCaptureCoverage(output+".2", "sensor", "bond0", "instance", "packet-sidecar", nil, old); err != nil {
		t.Fatal(err)
	}
	if err := writeCaptureCoverage(output+".1", "sensor", "bond0", "instance", "packet-sidecar", nil, newer); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(output+".2", start, start); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(output+".1", start.Add(time.Minute), start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output+".3.gz", []byte("not a plain JSONL rotation"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, nil, 0640); err != nil {
		t.Fatal(err)
	}
	got, found, err := lastPersistedCaptureCoverage(output, "sensor", "instance")
	if err != nil || !found || !got.To.Equal(newer.To) {
		t.Fatalf("numeric rotation lookup = %+v, found=%t err=%v", got, found, err)
	}
}
