package store

import (
	"fmt"
	"testing"
)

func TestCompactInventoryPreservesCandidatesAndEvidenceReferences(t *testing.T) {
	ids := []string{}
	for i := 0; i < 1000; i++ {
		ids = append(ids, fmt.Sprint(i))
	}
	signal := DeviceSignal{SignalID: "signal", SeenCount: 1000, EventIDs: ids}
	original := IPDeviceInventory{SuspectedDeviceCount: 2, Signals: []DeviceSignal{signal}, Devices: []ObservedDevice{{DeviceID: "a", Signals: []DeviceSignal{signal}}, {DeviceID: "b"}}}
	compact := compactCurrentInventory(original)
	if compact.SuspectedDeviceCount != 2 || len(compact.Devices) != 2 || compact.Signals[0].SeenCount != 1000 || len(compact.Signals[0].EventIDs) > 16 || len(compact.Devices[0].Signals[0].EventIDs) > 16 {
		t.Fatalf("unbounded or lost evidence: %+v", compact)
	}
	if len(original.Signals[0].EventIDs) != 1000 || len(original.Devices[0].Signals[0].EventIDs) != 1000 {
		t.Fatal("mutated original evidence")
	}
}
