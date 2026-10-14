package main

import (
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/realtime"
)

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
