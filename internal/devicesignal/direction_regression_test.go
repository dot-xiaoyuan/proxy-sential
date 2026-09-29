package devicesignal

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestPacketScopeDirectionAndNeighborIdentity(t *testing.T) {
	scope := &normalized.CaptureScope{UserCIDRs: []string{"192.168.0.0/24", "2001:db8:1::/64"}}
	for _, tc := range []struct{ src, dst, want string }{
		{"192.168.0.93", "203.0.113.1", "outbound"}, {"203.0.113.1", "192.168.0.93", "inbound"},
		{"192.168.0.93", "192.168.0.94", "internal"}, {"10.1.1.1", "203.0.113.1", "unknown"},
		{"2001:db8:1::1", "2001:db8:2::1", "outbound"},
	} {
		if got := scope.Direction(tc.src, tc.dst); got != tc.want {
			t.Fatalf("%s→%s direction %s", tc.src, tc.dst, got)
		}
	}
	if (*normalized.CaptureScope)(nil).Direction("192.168.0.93", "203.0.113.1") != "unknown" {
		t.Fatal("private IP inferred direction")
	}
	now := time.Now().UTC().Truncate(5 * time.Second)
	scope.SchemaVersion = "capture-scope/v1"
	scope.SensorID = "sensor"
	scope.CollectorInstanceID = "boot"
	scope.CampusID = "lab"
	scope.AccessDomain = "nas"
	scope.ValidFrom = now.Add(-time.Hour)
	scope.ValidUntil = now.Add(time.Hour)
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := writeBucketWithScope(path, "sensor", "mirror", "boot", scope, now, map[bucketKey]int{{IP: "192.168.0.93", MAC: "aa:bb:cc:dd:ee:ff", Direction: "outbound", Version: 4, TTL: 63}: 3}); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scan := bufio.NewScanner(file)
	if !scan.Scan() {
		t.Fatal("missing event")
	}
	var event normalized.Event
	if json.Unmarshal(scan.Bytes(), &event) != nil {
		t.Fatal("invalid event")
	}
	if _, exists := event.Subject["mac"]; exists {
		t.Fatal("neighbor MAC became terminal identity")
	}
	if event.Payload["neighbor_mac"] != "aa:bb:cc:dd:ee:ff" {
		t.Fatal("neighbor provenance lost")
	}
}
