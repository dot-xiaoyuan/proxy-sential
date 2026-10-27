package store

import (
	"testing"
	"time"

	"proxy-sentinel/internal/netscan"
)

func TestInternalScanFindingIDSeparatesDenseZonesAndBoundsRepeats(t *testing.T) {
	base := netscan.Finding{Mode: netscan.Dense, SensorID: "s", CampusID: "c", SourceIP: "10.9.0.1", ZoneIDs: []string{"a"}, WindowEnd: time.Date(2026, 10, 23, 12, 1, 0, 0, time.UTC)}
	id := InternalScanFindingID(base)
	other := base
	other.ZoneIDs = []string{"b"}
	if id == InternalScanFindingID(other) {
		t.Fatal("different dense zones collided")
	}
	other = base
	other.WindowEnd = other.WindowEnd.Add(2 * time.Minute)
	if id != InternalScanFindingID(other) {
		t.Fatal("same five-minute episode was duplicated")
	}
	other.WindowEnd = other.WindowEnd.Add(5 * time.Minute)
	if id == InternalScanFindingID(other) {
		t.Fatal("later episode was merged")
	}
}
