package discovery

import (
	"encoding/json"
	"testing"
)

func TestCaptureKernelStatsKeepSocketWideLossAcrossSamples(t *testing.T) {
	stats := NewCaptureStats()
	stats.recordKernelPacketWindow(120, 3, true)
	stats.recordKernelPacketWindow(40, 0, true)
	if !stats.Kernel.StatsKnown || stats.Kernel.Packets != 160 || stats.Kernel.Dropped != 3 {
		t.Fatalf("kernel packet windows were not accumulated: %+v", stats.Kernel)
	}
	stats.recordKernelPacketWindow(0, 0, false)
	if stats.Kernel.StatsKnown || stats.Kernel.Packets != 160 || stats.Kernel.Dropped != 3 {
		t.Fatalf("missing kernel statistics erased earlier loss: %+v", stats.Kernel)
	}
	raw, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Kernel struct {
			StatsKnown bool   `json:"stats_known"`
			Packets    uint64 `json:"packets"`
			Dropped    uint64 `json:"dropped"`
		} `json:"kernel_capture"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil || stored.Kernel.StatsKnown || stored.Kernel.Packets != 160 || stored.Kernel.Dropped != 3 {
		t.Fatalf("capture snapshot lost global kernel loss: %+v err=%v", stored, err)
	}
}
