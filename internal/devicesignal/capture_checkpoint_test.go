package devicesignal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
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

func TestRouterStartupCoveragePersistsFirstStartAndCorruptCheckpointLoss(t *testing.T) {
	for _, scenario := range []struct {
		name              string
		corruptCheckpoint bool
	}{{name: "first start"}, {name: "corrupt checkpoint", corruptCheckpoint: true}} {
		t.Run(scenario.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "ttl.jsonl")
			if scenario.corruptCheckpoint {
				if err := os.WriteFile(captureCoverageCheckpointPath(output), []byte("corrupt\n"), 0640); err != nil {
					t.Fatal(err)
				}
			}
			previous, found, priorErr := lastPersistedCaptureCoverage(output, "sensor", "instance")
			if found || (priorErr != nil) != scenario.corruptCheckpoint {
				t.Fatalf("lookup found=%t err=%v", found, priorErr)
			}
			bound := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
			start := bound.Add(12 * time.Millisecond)
			startup, continuityKnown := routerStartupCoverage(bound, start, previous, found, priorErr, 120, 9)
			if continuityKnown || !startup.From.Equal(bound) || !startup.To.Equal(start) || startup.Received != 120 || startup.Dropped != 9 || startup.KernelStatsKnown || !startup.Stopped || startup.Complete() {
				t.Fatalf("startup loss was not marked incomplete: %+v known=%t", startup, continuityKnown)
			}
			if err := writeCaptureCoverage(output, "sensor", "bond0", "instance", "packet-sidecar", nil, startup); err != nil {
				t.Fatal(err)
			}
			if err := saveCaptureCoverageCheckpoint(output, "sensor", "instance", startup); err != nil {
				t.Fatal(err)
			}
			got, found, err := lastPersistedCaptureCoverage(output, "sensor", "instance")
			if err != nil || !found || got.Dropped != 9 || !got.Stopped || !got.To.Equal(start) {
				t.Fatalf("persisted startup loss = %+v found=%t err=%v", got, found, err)
			}
		})
	}
}

func TestCaptureCoverageTailRequiresSuccessfulRecoverySync(t *testing.T) {
	output := filepath.Join(t.TempDir(), "ttl.jsonl")
	from := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	coverage := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: from, To: from.Add(30 * time.Second), KernelStatsKnown: true}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		t.Fatal(err)
	}
	event := normalized.Event{
		SchemaVersion: "v1", EventID: "coverage-unconfirmed", Source: "packet-sidecar", SourceEventType: "capture_coverage", Type: "device",
		Timestamp: coverage.To.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor", "collector_instance_id": "instance"},
		Subject: map[string]any{}, Payload: map[string]any{"capture_coverage": coverage},
	}
	if err := json.NewEncoder(file).Encode(event); err != nil {
		file.Close()
		t.Fatal(err)
	}
	// This deliberately closes a complete JSONL row without calling Sync,
	// matching an Encode success followed by a failed writer Sync.
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("injected fsync failure")
	got, found, err := readCaptureCoverageTailWithSync(output, "sensor", "instance", func(*os.File) error { return syncFailure })
	if !errors.Is(err, syncFailure) || found || !got.To.IsZero() {
		t.Fatalf("unconfirmed row was trusted: coverage=%+v found=%t err=%v", got, found, err)
	}
	got, found, err = readCaptureCoverageTail(output, "sensor", "instance")
	if err != nil || !found || !got.To.Equal(coverage.To) {
		t.Fatalf("recovery sync did not confirm row: coverage=%+v found=%t err=%v", got, found, err)
	}
}
