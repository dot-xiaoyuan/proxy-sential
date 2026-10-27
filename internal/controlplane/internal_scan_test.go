package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/netscan"
	"proxy-sentinel/internal/store"
)

type internalScanFake struct {
	store.Reader
	rules     []store.InternalScanRule
	zones     []netscan.Zone
	attempts  []netscan.Attempt
	queryErr  error
	findings  []netscan.Finding
	evidence  []evidence.Evidence
	runStatus string
}

func (f *internalScanFake) ListInternalScanRules(context.Context) ([]store.InternalScanRule, []netscan.Zone, error) {
	return f.rules, f.zones, nil
}
func (f *internalScanFake) ListInternalScanAttempts(context.Context, time.Time, []string, int) ([]netscan.Attempt, error) {
	return f.attempts, f.queryErr
}
func (f *internalScanFake) WriteInternalScanFindings(_ context.Context, items []netscan.Finding) error {
	f.findings = append(f.findings, items...)
	return nil
}
func (f *internalScanFake) WriteEvidence(_ context.Context, items []evidence.Evidence) error {
	f.evidence = append(f.evidence, items...)
	return nil
}
func (f *internalScanFake) WriteInternalScanRun(_ context.Context, _ time.Time, status, _ string, _, _ int) error {
	f.runStatus = status
	return nil
}

func TestInternalScanWorkerWritesWeakEvidence(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &internalScanFake{rules: []store.InternalScanRule{{CampusID: "c", Config: netscan.Config{Enabled: true}}}, zones: []netscan.Zone{{ID: "z", CampusID: "c", CIDR: "10.1.0.0/24"}}}
	for i := 1; i <= 50; i++ {
		f.attempts = append(f.attempts, netscan.Attempt{SensorID: "s", CampusID: "c", ConnectionID: fmt.Sprint(i), EventID: fmt.Sprintf("event-%d", i), SourceIP: "10.9.0.1", DestinationIP: fmt.Sprintf("10.1.0.%d", i), DestinationPort: 445, State: netscan.Failed, At: now.Add(-time.Minute)})
	}
	(&Server{reader: f}).processInternalScans(now)
	if len(f.findings) != 1 || len(f.evidence) != 1 {
		t.Fatalf("findings=%+v evidence=%+v", f.findings, f.evidence)
	}
	if f.runStatus != "complete" {
		t.Fatalf("run status=%s", f.runStatus)
	}
	if f.evidence[0].Score > 30 || f.evidence[0].Window == "" || f.evidence[0].Confidence == 0 {
		t.Fatalf("weak evidence missing explanation: %+v", f.evidence[0])
	}
	f.findings = nil
	f.evidence = nil
	f.queryErr = errors.New("truncated")
	(&Server{reader: f}).processInternalScans(now)
	if len(f.findings) != 0 || len(f.evidence) != 0 {
		t.Fatal("incomplete input must not produce evidence")
	}
	if f.runStatus != "incomplete" {
		t.Fatalf("run status=%s", f.runStatus)
	}
	f.queryErr = nil
	f.attempts = nil
	(&Server{reader: f}).processInternalScans(now)
	if f.runStatus != "incomplete" {
		t.Fatalf("empty capture status=%s", f.runStatus)
	}
}
