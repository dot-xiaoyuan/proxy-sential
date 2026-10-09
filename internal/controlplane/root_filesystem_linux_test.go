//go:build linux

package controlplane

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func TestRootFilesystemLinuxProbe(t *testing.T) {
	status, err := readRootFilesystemStatus()
	if err != nil || status == nil || status.Path != "/" || status.TotalBytes == 0 || status.UsedBytes > status.TotalBytes || status.AvailableBytes > status.TotalBytes-status.UsedBytes || math.IsNaN(status.UsedPercent) || math.IsInf(status.UsedPercent, 0) || status.UsedPercent < 0 || status.UsedPercent > 100 {
		t.Fatalf("native root capacity is invalid: %+v %v", status, err)
	}
	raw, err := json.Marshal(captureRuntimeStatus(nil, time.Time{}))
	if err != nil || !strings.Contains(string(raw), `"root_filesystem":`) || strings.Contains(string(raw), `"root_filesystem_error":`) {
		t.Fatalf("a valid native capacity must reach the runtime response: %s %v", raw, err)
	}
}
