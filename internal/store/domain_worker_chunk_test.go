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
