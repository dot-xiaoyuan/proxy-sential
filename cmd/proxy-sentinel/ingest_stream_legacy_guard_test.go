package main

import (
	"testing"

	"proxy-sentinel/internal/realtime"
)

func TestLegacyIngestNeverReopensAuditedStreamOwnedFile(t *testing.T) {
	sources := []realtime.Source{{Kind: "zeek-dhcp", Path: "/zeek/dhcp.log"}, {Kind: "device-signals", Path: "/signals/ttl.jsonl"}}
	owners := map[string]string{"zeek-dhcp\x00/zeek/dhcp.log": "sensor-a"}
	legacy, transferred, err := filterLegacyStreamOwnedSources("sensor-a", sources, owners)
	if err != nil || len(legacy) != 1 || legacy[0].Path != "/signals/ttl.jsonl" || len(transferred) != 1 {
		t.Fatalf("active cutover was not isolated from old checkpoint: legacy=%+v transferred=%+v err=%v", legacy, transferred, err)
	}
	owners["zeek-dhcp\x00/zeek/dhcp.log"] = "sensor-b"
	if _, _, err := filterLegacyStreamOwnedSources("sensor-a", sources, owners); err == nil {
		t.Fatal("cross-sensor source ownership mismatch was hidden")
	}
}
