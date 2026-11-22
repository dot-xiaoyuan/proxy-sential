package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/realtime"
)

func TestDeviceDiscoveryMenuFollowsServiceIntent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-expectations.json")
	if deviceDiscoveryMenuHidden(path) {
		t.Fatal("deployments without explicit service intent should retain the discovery menu")
	}
	for _, tt := range []struct {
		intent string
		hidden bool
	}{
		{intent: "stopped", hidden: true},
		{intent: "running", hidden: false},
	} {
		t.Run(tt.intent, func(t *testing.T) {
			raw := `{"proxy-sentinel-discovery.service":"` + tt.intent + `","proxy-sentinel-passive-discovery.service":"running"}`
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if got := deviceDiscoveryMenuHidden(path); got != tt.hidden {
				t.Fatalf("menu hidden = %v, want %v", got, tt.hidden)
			}
		})
	}
}

func TestRiskWorkerLoopsProcessIndependentBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 2)
	done := make(chan struct{})
	go func() {
		runRiskWorkerLoops(ctx, time.Hour, 2, func(bool) bool {
			started <- struct{}{}
			<-ctx.Done()
			return false
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

func TestRiskWorkerScheduleAdaptsToFullBatchesAndDatabaseLatency(t *testing.T) {
	for _, tt := range []struct {
		name              string
		interval, elapsed time.Duration
		full, draining    bool
		wantDrain         bool
		want              time.Duration
	}{
		{"full", time.Second, 180 * time.Millisecond, true, false, true, 320 * time.Millisecond},
		{"larger batch stays within budget", time.Second, 550 * time.Millisecond, true, true, true, 0},
		{"partial or failed", time.Second, 180 * time.Millisecond, false, true, false, 820 * time.Millisecond},
		{"back to small batch", time.Second, 550 * time.Millisecond, true, false, false, 450 * time.Millisecond},
		{"minimum interval", 150 * time.Millisecond, 20 * time.Millisecond, true, false, true, 80 * time.Millisecond},
		{"batch outlasts the interval", time.Second, 2 * time.Second, true, true, false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if drain, delay := riskWorkerSchedule(tt.interval, tt.elapsed, tt.full, tt.draining); drain != tt.wantDrain || delay != tt.want {
				t.Fatalf("drain=%t delay=%v, want drain=%t delay=%v", drain, delay, tt.wantDrain, tt.want)
			}
		})
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
