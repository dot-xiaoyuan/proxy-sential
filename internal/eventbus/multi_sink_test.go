package eventbus

import (
	"context"
	"errors"
	"testing"
)

type recordingSink struct {
	calls int
	err   error
}

func (s *recordingSink) WriteReceipts(context.Context, []Receipt) error {
	s.calls++
	return s.err
}

func TestMultiSinkRunsInOrderAndStopsOnError(t *testing.T) {
	first := &recordingSink{}
	second := &recordingSink{}
	sink := NewMultiSink(first, nil, second)
	if err := sink.WriteReceipts(context.Background(), []Receipt{{EventID: "e"}}); err != nil {
		t.Fatal(err)
	}
	if first.calls != 1 || second.calls != 1 {
		t.Fatalf("unexpected calls: %d %d", first.calls, second.calls)
	}
	first.err = errors.New("boom")
	if err := sink.WriteReceipts(context.Background(), []Receipt{{EventID: "e"}}); err == nil {
		t.Fatal("expected error")
	}
	if second.calls != 1 {
		t.Fatal("second sink should not run after failure")
	}
}
