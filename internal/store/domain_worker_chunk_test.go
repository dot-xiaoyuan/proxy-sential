package store

import (
	"errors"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func chunkProbeEvents(n int) []normalized.Event {
	events := make([]normalized.Event, 0, n)
	for i := 0; i < n; i++ {
		events = append(events, normalized.Event{Type: "device"})
	}
	return events
}

// 身份写入串行在同一个事务级 advisory lock 上，所以 ingest 的整批事件必须切成有界事务，
// 否则单次持锁可达上百秒并饿死其它写入。
func TestWriteInChunksBoundsEachTransaction(t *testing.T) {
	var sizes []int
	if err := writeInChunks(chunkProbeEvents(400), 150, func(chunk []normalized.Event) error {
		sizes = append(sizes, len(chunk))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []int{150, 150, 100}
	if len(sizes) != len(want) {
		t.Fatalf("chunk sizes = %v, want %v", sizes, want)
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Fatalf("chunk sizes = %v, want %v", sizes, want)
		}
	}
}

// 失败必须立刻停止，不能继续写后续块。
func TestWriteInChunksStopsOnFirstFailure(t *testing.T) {
	sentinel := errors.New("boom")
	calls := 0
	err := writeInChunks(chunkProbeEvents(450), 150, func([]normalized.Event) error {
		calls++
		if calls == 2 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) || calls != 2 {
		t.Fatalf("err=%v calls=%d, want the sentinel after two chunks", err, calls)
	}
}

func TestWriteInChunksHandlesEmptyAndDegenerateSizes(t *testing.T) {
	calls := 0
	if err := writeInChunks(nil, 150, func([]normalized.Event) error { calls++; return nil }); err != nil || calls != 0 {
		t.Fatalf("empty input must not call the writer: err=%v calls=%d", err, calls)
	}
	sizes := []int{}
	if err := writeInChunks(chunkProbeEvents(3), 0, func(chunk []normalized.Event) error {
		sizes = append(sizes, len(chunk))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 3 {
		t.Fatalf("chunk<1 must degrade to one event per call, got %v", sizes)
	}
}

// 站点用环境变量提高域名识别并发度；越界或非法值必须退回单 worker 的默认行为。
func TestDomainWorkerCountBounds(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
	}{
		{"", 1}, {"4", 4}, {"16", 16}, {"17", 1}, {"0", 1}, {"-2", 1}, {"abc", 1}, {" 3 ", 3},
	} {
		t.Setenv("PROXY_SENTINEL_DOMAIN_WORKERS", tc.value)
		if got := domainWorkerCount(); got != tc.want {
			t.Fatalf("domainWorkerCount(%q) = %d, want %d", tc.value, got, tc.want)
		}
	}
}

// The chunk size is a field-tunable knob, so its bounds are pinned: below the historical bound
// it would multiply the commit count (and with it the WAL fsyncs that dominate this path), and
// above the ceiling one transaction would hold the identity write lock for too long.
func TestDomainIdentityChunkSizeBounds(t *testing.T) {
	cases := []struct {
		set  string
		want int
	}{
		{"", identitySignalBatchSize},
		{"abc", identitySignalBatchSize},
		{"0", identitySignalBatchSize},
		{"149", identitySignalBatchSize},
		{"150", 150},
		{"1000", 1000},
		{"5000", 5000},
		{"5001", identitySignalBatchSize},
	}
	for _, item := range cases {
		t.Setenv("PROXY_SENTINEL_DOMAIN_IDENTITY_CHUNK", item.set)
		if got := domainIdentityChunkSize(); got != item.want {
			t.Fatalf("chunk size for %q = %d, want %d", item.set, got, item.want)
		}
	}
}
