package realtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/ingest"
	"testing"
	"time"
)

func TestRunRecordsFailedSourceWithoutHidingHealthySource(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	healthy := filepath.Join(dir, "good.json")
	if err := os.WriteFile(healthy, []byte(rotationDNS("10.0.0.2")), 0600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := Run(ctx, backend, Options{SensorID: "failure", Sources: []Source{{Kind: "suricata", Path: missing}, {Kind: "suricata", Path: healthy}}, PollInterval: time.Millisecond, StoreTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	failures := 0
	for _, d := range backend.diagnostics {
		if d.Type == "source_error" && d.Severity == "error" && d.RawRef["source"] == missing {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("failed source invisible or unbounded errors: count=%d diagnostics=%+v", failures, backend.diagnostics)
	}
	if len(backend.events) != 1 || backend.events[0].Subject["ip"] != "10.0.0.2" {
		t.Fatalf("healthy source blocked: %+v", backend.events)
	}
}

func TestRunCancellationDoesNotRecordSourceFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backend := &fakeBackend{}
	if err := Run(ctx, backend, Options{SensorID: "cancel", Sources: []Source{{Kind: "suricata", Path: filepath.Join(t.TempDir(), "missing")}}}); err != nil {
		t.Fatal(err)
	}
	if len(backend.diagnostics) != 0 {
		t.Fatalf("shutdown recorded source activity: %+v", backend.diagnostics)
	}
}

type deadlineBackend struct {
	fakeBackend
	budget time.Duration
}

func (b *deadlineBackend) WriteIngestDiagnostics(ctx context.Context, _ []ingest.Diagnostic) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fmt.Errorf("missing reporting deadline")
	}
	b.budget = time.Until(deadline)
	return fmt.Errorf("diagnostic storage unavailable")
}
func TestSourceFailureReportingHasIndependentBoundedDeadline(t *testing.T) {
	for _, timeout := range []time.Duration{time.Minute, 10 * time.Millisecond} {
		b := &deadlineBackend{}
		err := writeSourceFailure(context.Background(), b, Options{SensorID: "failure", StoreTimeout: timeout}, Source{Kind: "suricata", Path: "/tmp/fixture"}, fmt.Errorf("fixture error"))
		if err == nil {
			t.Fatal("diagnostic storage error hidden")
		}
		limit := timeout
		if limit > 5*time.Second {
			limit = 5 * time.Second
		}
		if b.budget <= 0 || b.budget > limit {
			t.Fatalf("unbounded reporting: budget=%s limit=%s", b.budget, limit)
		}
	}
}
