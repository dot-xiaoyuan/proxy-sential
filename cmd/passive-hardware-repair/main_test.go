package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/store"
)

func TestRepairCheckpointNeverAdvancesBeforeCommitOrDurableAudit(t *testing.T) {
	state := repairCheckpoint{SchemaVersion: checkpointSchema, ManifestSHA256: "frozen", Total: 2, Outcomes: []store.HardwareRepairOutcome{}}
	failure := errors.New("failure")
	apply := func(context.Context, int, int) ([]store.HardwareRepairOutcome, error) { return nil, failure }
	saves := 0
	save := func(repairCheckpoint) error { saves++; return nil }
	if err := advanceRepair(context.Background(), &state, 25, apply, save); !errors.Is(err, failure) || state.Next != 0 || saves != 0 {
		t.Fatal("failed transaction advanced checkpoint")
	}
	calls := 0
	apply = func(_ context.Context, start, limit int) ([]store.HardwareRepairOutcome, error) {
		calls++
		if start != 0 {
			t.Fatal("retry skipped uncertain commit")
		}
		return []store.HardwareRepairOutcome{{Index: 0, Status: "admitted"}, {Index: 1, Status: "excluded", Reason: "missing_source_reference"}}, nil
	}
	if err := advanceRepair(context.Background(), &state, 25, apply, func(repairCheckpoint) error { return failure }); !errors.Is(err, failure) || state.Next != 0 {
		t.Fatal("failed audit write advanced checkpoint")
	}
	if err := advanceRepair(context.Background(), &state, 25, apply, save); err != nil || state.Next != 2 || !state.Complete || calls != 2 {
		t.Fatalf("retry did not reconcile: %+v %v", state, err)
	}
}
func TestRepairCheckpointRejectsSilentPartialCompletion(t *testing.T) {
	state := repairCheckpoint{Total: 2}
	for _, rows := range [][]store.HardwareRepairOutcome{nil, {{Index: 1, Status: "admitted"}}, {{Index: 0, Status: "complete"}}} {
		err := advanceRepair(context.Background(), &state, 25, func(context.Context, int, int) ([]store.HardwareRepairOutcome, error) { return rows, nil }, func(repairCheckpoint) error { return nil })
		if err == nil || state.Next != 0 {
			t.Fatal("malformed progress accepted")
		}
	}
}
func TestRepairAtomicArtifactsArePrivateAndManifestCannotBeReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := writeRepairJSON(path, map[string]string{"version": "one"}, true); err != nil {
		t.Fatal(err)
	}
	if err := writeRepairJSON(path, map[string]string{"version": "two"}, true); err == nil {
		t.Fatal("frozen manifest overwritten")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("artifact is not private")
	}
	var v map[string]string
	if err := readRepairJSON(path, &v); err != nil || v["version"] != "one" {
		t.Fatal("failed write changed original")
	}
	if err := writeRepairJSON(path, map[string]string{"version": "two"}, false); err != nil {
		t.Fatal(err)
	}
	if err := readRepairJSON(path, &v); err != nil || v["version"] != "two" {
		t.Fatal("checkpoint replace failed")
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := writeRepairJSON(link, v, false); err == nil {
		t.Fatal("symlink checkpoint allowed")
	}
}
