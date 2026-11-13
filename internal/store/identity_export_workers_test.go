package store

import "testing"

func TestIdentityExportWorkersStayBoundedAndCanReturnToOne(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS", "false")
	t.Setenv("PROXY_SENTINEL_IDENTITY_EXPORT_WORKERS", "")
	if got := identityExportWorkerCount(); got != 1 {
		t.Fatalf("legacy default workers=%d", got)
	}
	t.Setenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS", "true")
	if got := identityExportWorkerCount(); got != 1 {
		t.Fatalf("fresh split default workers=%d", got)
	}
	t.Setenv("PROXY_SENTINEL_IDENTITY_EXPORT_WORKERS", "1")
	if got := identityExportWorkerCount(); got != 1 {
		t.Fatalf("single-worker recovery setting ignored: %d", got)
	}
	t.Setenv("PROXY_SENTINEL_IDENTITY_EXPORT_WORKERS", "2")
	if got := identityExportWorkerCount(); got != 2 {
		t.Fatalf("bounded parallel setting ignored: %d", got)
	}
	t.Setenv("PROXY_SENTINEL_IDENTITY_EXPORT_WORKERS", "12")
	if got := identityExportWorkerCount(); got != 1 {
		t.Fatalf("unbounded worker request accepted: %d", got)
	}
}
