package controlplane

import (
	"testing"

	"proxy-sentinel/internal/fingerprint"
)

func TestFingerprintHistoryDisabledPreservesUnprocessedStatus(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_FINGERPRINT_HISTORY_BACKFILL", "false")
	manager := fingerprint.NewManager(t.TempDir())
	manager.SetBackfill("failed", 17)
	manager.SetDomainBackfill("pending", 3)
	s := &Server{fingerprints: manager}
	s.startFingerprintBackfill(manager.Status().Version)
	s.startDeviceProfileBackfill(manager.Status().Version)
	status := manager.Status()
	if status.BackfillStatus != "failed" || status.BackfillProcessed != 17 || status.DomainBackfillStatus != "pending" || status.DomainBackfillProcessed != 3 {
		t.Fatalf("disabled history must preserve outstanding work, got %+v", status)
	}
}
