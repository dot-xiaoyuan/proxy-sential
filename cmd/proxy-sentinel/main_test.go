package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/realtime"
)

func TestRiskWorkerLoopsProcessIndependentBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 2)
	done := make(chan struct{})
	go func() {
		runRiskWorkerLoops(ctx, time.Hour, 2, func() {
			started <- struct{}{}
			<-ctx.Done()
		})
		close(done)
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("risk worker waited for the other batch")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("risk workers did not stop after cancellation")
	}
}

// The ingest service is not a capture framework, so the collector it registers
// must name the dominant producer of the configured input.
func TestDeriveCollectorKindPrefersTheCaptureProducer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sources []realtime.Source
		want    string
	}{
		{"device signal wins over zeek", []realtime.Source{{Kind: "zeek-dhcp"}, {Kind: "device-signals"}}, "device-signal"},
		{"shared signal sidecar", []realtime.Source{{Kind: "shared-device-signals"}}, "device-signal"},
		{"suricata input", []realtime.Source{{Kind: "suricata"}}, "suricata"},
		{"zeek input", []realtime.Source{{Kind: "zeek-dhcp"}, {Kind: "zeek-software"}}, "zeek"},
		{"declared order does not change the answer", []realtime.Source{{Kind: "suricata"}, {Kind: "zeek-dhcp"}}, "suricata"},
		{"nothing configured", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveCollectorKind(tc.sources); got != tc.want {
				t.Fatalf("deriveCollectorKind(%v) = %q, want %q", tc.sources, got, tc.want)
			}
		})
	}
}

func TestOpenOutputWithParentsCreatesNestedDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow", "evaluation", "latest.json")
	output, closeOutput, err := openOutputWithParents(path)
	if err != nil {
		t.Fatalf("open nested output: %v", err)
	}
	if _, err := output.WriteString("{}\n"); err != nil {
		t.Fatalf("write nested output: %v", err)
	}
	if err := closeOutput(); err != nil {
		t.Fatalf("close nested output: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("nested output was not created: %v", err)
	}
}

// Skipping backlog discarded more than 110 million identity and device facts on the
// field. A leftover PROXY_SENTINEL_MAX_BACKLOG in runtime.env must stop every command
// instead of being silently ignored.
func TestRunRefusesRetiredBacklogSkip(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_MAX_BACKLOG", "5m")
	if err := run([]string{"read-model", "run"}); err == nil || err.Error() != retiredBacklogSkipError {
		t.Fatalf("expected refusal, got %v", err)
	}
}
