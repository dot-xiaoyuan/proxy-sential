package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestIdentityDeltaIgnoresConfirmationAndProvenance(t *testing.T) {
	a := AccountSession{SessionID: "s", AccountID: "a", IP: "192.0.2.1", StartedAt: "2026-10-01T00:00:00Z", LastConfirmedAt: "2026-10-22T00:00:00Z", RawRef: map[string]any{"snapshot": "a"}}
	b := a
	b.LastConfirmedAt = "2026-10-23T00:00:00Z"
	b.RawRef = map[string]any{"snapshot": "b"}
	if identityMemberFingerprint(a) != identityMemberFingerprint(b) {
		t.Fatal("confirmation-only snapshot must not dirty membership")
	}
	b.AccountID = "b"
	if identityMemberFingerprint(a) == identityMemberFingerprint(b) {
		t.Fatal("account reuse must change membership")
	}
}

func TestIdentityDeltaBatchesKeepIPsAtomic(t *testing.T) {
	rows := []identityDeltaMember{{IP: "192.0.2.1", SessionID: "a", Document: json.RawMessage(`{}`)}, {IP: "192.0.2.1", SessionID: "b", Document: json.RawMessage(`{}`)}, {IP: "192.0.2.2", SessionID: "c", Document: json.RawMessage(`{}`)}}
	batch, err := identityDeltaBatch(rows, 1, 1024)
	if err != nil || len(batch) != 2 {
		t.Fatalf("batch=%v err=%v", batch, err)
	}
	if _, err = identityDeltaBatch(rows, 1, 1); err == nil {
		t.Fatal("oversized IP must fail visibly")
	}
}

func TestIdentityDeltaPressureRequiresTwoHealthySamples(t *testing.T) {
	var p identityDeltaPressure
	if p.allow(6*time.Second, false) {
		t.Fatal("backlog must pause")
	}
	if p.allow(time.Second, false) {
		t.Fatal("one healthy sample cannot resume")
	}
	if !p.allow(time.Second, false) {
		t.Fatal("two healthy samples should resume")
	}
	if p.allow(0, true) {
		t.Fatal("database contention must pause")
	}
}

func TestIdentityDeltaBatchRecoversAfterTransientSlowStorage(t *testing.T) {
	for _, tt := range []struct {
		size    int
		elapsed time.Duration
		err     error
		want    int
	}{
		{100, 6 * time.Second, nil, 50}, {12, 500 * time.Millisecond, nil, 24},
		{64, 500 * time.Millisecond, nil, 128}, {100, 500 * time.Millisecond, nil, 200}, {400, 500 * time.Millisecond, nil, 500}, {500, 500 * time.Millisecond, nil, 500},
		{50, 2 * time.Second, nil, 50}, {50, 6 * time.Second, errIdentityDeltaPressure, 50},
		{12, time.Second, context.DeadlineExceeded, 6}, {1, 6 * time.Second, nil, 1},
	} {
		if got := nextIdentityDeltaBatch(tt.size, tt.elapsed, tt.err); got != tt.want {
			t.Fatalf("size=%d elapsed=%s err=%v got=%d want=%d", tt.size, tt.elapsed, tt.err, got, tt.want)
		}
	}
}
