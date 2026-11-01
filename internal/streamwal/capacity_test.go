package streamwal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func appendCapacityRecord(t *testing.T, l *Log, class AppendClass, id string) Result {
	t.Helper()
	future, err := l.AppendWithClass(context.Background(), Record{Kind: "lane", ID: id, Payload: make([]byte, 32)}, class)
	if err != nil {
		t.Fatal(err)
	}
	result := <-future
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	return result
}

func requireCapacityRejection(t *testing.T, future <-chan Result, err error) {
	t.Helper()
	if future != nil || !errors.Is(err, ErrCapacity) || !errors.Is(err, ErrNotWritten) || errors.Is(err, ErrIndeterminate) || errors.Is(err, ErrStopped) {
		t.Fatalf("capacity must reject before admission without stopping: future=%v err=%v", future != nil, err)
	}
}

func TestDataCapacityDoesNotPoisonControlDrain(t *testing.T) {
	l, _, dir := openTestLog(t, Options{MaxBatchBytes: 512, MaxLogBytes: 4096, MaxDataBytes: 512, ControlReserveBytes: 2048})
	record := Record{Kind: "accept", ID: "accepted", Payload: make([]byte, 200)}
	future, err := l.AppendWithClass(context.Background(), record, Data)
	if err != nil {
		t.Fatal(err)
	}
	first := <-future
	if first.Err != nil {
		t.Fatal(first.Err)
	}
	record.ID = "rejected"
	future, err = l.AppendWithClass(context.Background(), record, Data)
	requireCapacityRejection(t, future, err)
	for _, id := range []string{"archive-attempt", "archive-ack", "projection-attempt", "projection-ack", "search-attempt", "search-ack", "finalized"} {
		appendCapacityRecord(t, l, Control, id)
	}
	if _, err := l.Read(first.Receipt); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("capacity poisoned writer close: %v", err)
	}
	info, err := Inspect(dir, Options{})
	if err != nil || info.Records != 8 {
		t.Fatalf("accepted work was not drainable: %+v %v", info, err)
	}
}

func TestCapacityCountsQueuedInflightAndEachPossibleSeal(t *testing.T) {
	l, f, _ := openTestLog(t, Options{MaxBatchBytes: 256, MaxBatchRecords: 1, MaxLogBytes: 888, MaxDataBytes: 500, ControlReserveBytes: 388})
	f.mu.Lock()
	f.block, f.entered = make(chan struct{}), make(chan struct{}, 1)
	block, entered := f.block, f.entered
	f.mu.Unlock()
	var unblock sync.Once
	defer unblock.Do(func() { close(block) })
	record := Record{Kind: "k", ID: "x", Payload: make([]byte, 32)} // 102-byte frame plus a 120-byte seal.
	first, err := l.AppendWithClass(context.Background(), record, Data)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	second, err := l.AppendWithClass(context.Background(), record, Data)
	if err != nil {
		t.Fatal(err)
	}
	future, err := l.AppendWithClass(context.Background(), record, Data)
	requireCapacityRejection(t, future, err)
	third, err := l.AppendWithClass(context.Background(), record, Control)
	if err != nil {
		t.Fatal(err)
	}
	fourth, err := l.AppendWithClass(context.Background(), record, Control)
	if err != nil {
		t.Fatal(err)
	}
	future, err = l.AppendWithClass(context.Background(), record, Control)
	requireCapacityRejection(t, future, err)
	if usage := l.Usage(); usage.DurableBytes != 0 || usage.ReservedBytes != 888 || usage.QueuedRecords != 4 || usage.ControlAvailableBytes != 0 || usage.Stopped {
		t.Fatalf("in-flight/waiting reservations not charged: %+v", usage)
	}
	unblock.Do(func() { close(block) })
	for _, future := range []<-chan Result{first, second, third, fourth} {
		if result := <-future; result.Err != nil {
			t.Fatal(result.Err)
		}
	}
	if end := l.durableSnapshot().EndOffset; end != 888 {
		t.Fatalf("unexpected sealed byte count: %d", end)
	}
	if usage := l.Usage(); usage.ReservedBytes != 0 || usage.QueuedRecords != 0 || usage.ControlAvailableBytes != 0 || usage.Stopped {
		t.Fatalf("reservations were leaked or writer stopped at exact ceiling: %+v", usage)
	}
}

func TestGroupedSealsRefundAdmissionSpace(t *testing.T) {
	l, _, _ := openTestLog(t, Options{MaxBatchBytes: 700, MaxLogBytes: 1000, MaxDataBytes: 700, ControlReserveBytes: 200, Linger: 30 * time.Millisecond})
	record := Record{Kind: "k", ID: "x", Payload: make([]byte, 32)}
	var futures []<-chan Result
	for range 3 {
		future, err := l.AppendWithClass(context.Background(), record, Data)
		if err != nil {
			t.Fatal(err)
		}
		futures = append(futures, future)
	}
	for _, future := range futures {
		if result := <-future; result.Err != nil {
			t.Fatal(result.Err)
		}
	}
	if end := l.durableSnapshot().EndOffset; end != 426 {
		t.Fatalf("fixture did not form one group: %d", end)
	}
	if usage := l.Usage(); usage.ReservedBytes != 0 || usage.DataAvailableBytes != 274 {
		t.Fatalf("seal refund was not reflected in admission: %+v", usage)
	}
	// Three worst-case seals were reserved; only one was written. The returned
	// space must admit another complete record without double-counting the group.
	future, err := l.AppendWithClass(context.Background(), record, Data)
	if err != nil {
		t.Fatalf("unused seal reservation was retained: %v", err)
	}
	if result := <-future; result.Err != nil {
		t.Fatal(result.Err)
	}
}

func TestLowerDataBudgetAllowsRecoveryAndControlDrain(t *testing.T) {
	l, _, dir := openTestLog(t, Options{})
	first := appendCapacityRecord(t, l, Data, "a")
	appendCapacityRecord(t, l, Data, "b")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	opts := Options{MaxBatchBytes: 512, MaxLogBytes: 4096, MaxDataBytes: 1, ControlReserveBytes: 1024}
	reopened, err := Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Read(first.Receipt); err != nil {
		t.Fatal(err)
	}
	future, err := reopened.Append(context.Background(), Record{Kind: "accept", ID: "new"})
	requireCapacityRejection(t, future, err)
	appendCapacityRecord(t, reopened, Control, "ack")
}

func TestLowerTotalBudgetAllowsReadButNeverOvershootsHardLimit(t *testing.T) {
	l, _, dir := openTestLog(t, Options{})
	first := appendCapacityRecord(t, l, Data, "a")
	appendCapacityRecord(t, l, Data, "b")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	opts := Options{MaxLogBytes: 256, ControlReserveBytes: 64}
	info, err := Inspect(dir, opts)
	if err != nil || info.Records != 2 {
		t.Fatalf("lower write ceiling prevented inspection: %+v %v", info, err)
	}
	reopened, err := Open(dir, opts)
	if err != nil {
		t.Fatalf("lower write ceiling prevented recovery: %v", err)
	}
	defer reopened.Close()
	count := 0
	if err := reopened.Replay(func(Entry) error { count++; return nil }); err != nil || count != 2 {
		t.Fatalf("replay lost accepted work: %d %v", count, err)
	}
	if _, err := reopened.Read(first.Receipt); err != nil {
		t.Fatal(err)
	}
	for _, class := range []AppendClass{Data, Control} {
		future, err := reopened.AppendWithClass(context.Background(), Record{Kind: "lane", ID: "no-space"}, class)
		requireCapacityRejection(t, future, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("read-only capacity state poisoned Close: %v", err)
	}
}

func TestCapacityOptionsRejectAmbiguousCombinations(t *testing.T) {
	for _, opts := range []Options{
		{MaxLogBytes: -1},
		{MaxDataBytes: -1},
		{ControlReserveBytes: -1},
		{MaxLogBytes: 1000, ControlReserveBytes: 1000},
		{MaxLogBytes: 1000, ControlReserveBytes: 100, MaxDataBytes: 901},
		{MaxLogBytes: maxLogBytes + 1},
	} {
		if _, err := opts.normalized(); !errors.Is(err, ErrBounds) {
			t.Fatalf("invalid capacity options accepted: %+v %v", opts, err)
		}
	}
	opts, err := (Options{}).normalized()
	if err != nil || opts.ControlReserveBytes != 16<<20 || opts.MaxDataBytes != (1<<30)-(16<<20) {
		t.Fatalf("unexpected default reserve: %+v %v", opts, err)
	}
	if _, err := (Options{MaxLogBytes: 1}).normalized(); err != nil {
		t.Fatalf("tiny read-only write budget was rejected: %v", err)
	}
	l, _, _ := openTestLog(t, Options{})
	if future, err := l.AppendWithClass(context.Background(), Record{Kind: "lane", ID: "x"}, AppendClass(255)); future != nil || !errors.Is(err, ErrBounds) {
		t.Fatalf("unknown record class accepted: %v %v", future != nil, err)
	}
}

func TestControlIOFailureRemainsUnknownAndStopsWriter(t *testing.T) {
	for _, mode := range []string{"sync", "short", "write"} {
		t.Run(mode, func(t *testing.T) {
			l, f, _ := openTestLog(t, Options{})
			f.mu.Lock()
			f.short, f.failSync, f.failWrite = mode == "short", mode == "sync", mode == "write"
			f.mu.Unlock()
			future, err := l.AppendWithClass(context.Background(), Record{Kind: "lane", ID: "attempted"}, Control)
			if err != nil {
				t.Fatal(err)
			}
			result := <-future
			if !errors.Is(result.Err, ErrIndeterminate) || errors.Is(result.Err, ErrNotWritten) || mode == "short" && !errors.Is(result.Err, io.ErrShortWrite) {
				t.Fatalf("I/O failure disguised as capacity rejection: %v", result.Err)
			}
			if _, err := l.AppendWithClass(context.Background(), Record{Kind: "lane", ID: "retry"}, Control); !errors.Is(err, ErrStopped) {
				t.Fatalf("unknown write did not stop writer: %v", err)
			}
			if err := l.Close(); !errors.Is(err, ErrIndeterminate) {
				t.Fatalf("close hid unknown outcome: %v", err)
			}
			if usage := l.Usage(); !usage.Stopped || usage.ReservedBytes != 0 || usage.QueuedRecords != 0 || usage.DataAvailableBytes != 0 || usage.ControlAvailableBytes != 0 {
				t.Fatalf("failed writer exposed unused reservation as writable: %+v", usage)
			}
		})
	}
}

func TestConcurrentDataAndControlAdmissionNeverOversellsHardLimit(t *testing.T) {
	l, _, _ := openTestLog(t, Options{MaxBatchBytes: 700, MaxLogBytes: 2048, MaxDataBytes: 1024, ControlReserveBytes: 1024, Linger: time.Millisecond})
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			class := Data
			if i%2 == 0 {
				class = Control
			}
			future, err := l.AppendWithClass(context.Background(), Record{Kind: "lane", ID: fmt.Sprint(i), Payload: make([]byte, 32)}, class)
			if err != nil {
				if future != nil || !errors.Is(err, ErrNotWritten) || !errors.Is(err, ErrCapacity) {
					t.Errorf("unexpected admission outcome: %v", err)
				}
				return
			}
			if result := <-future; result.Err != nil {
				t.Errorf("admitted record failed after capacity reservation: %v", result.Err)
			}
		}()
	}
	wg.Wait()
	usage := l.Usage()
	if usage.DurableBytes > 2048 || usage.ReservedBytes != 0 || usage.QueuedRecords != 0 || usage.Stopped {
		t.Fatalf("concurrent capacity invariant failed: %+v", usage)
	}
}

func TestUnknownGroupReleasesHeldAndQueuedReservationsExactlyOnce(t *testing.T) {
	l, f, _ := openTestLog(t, Options{MaxBatchBytes: 256, MaxLogBytes: 2048, MaxDataBytes: 1024, ControlReserveBytes: 1024, Linger: 30 * time.Millisecond})
	f.mu.Lock()
	f.block, f.entered, f.failSync = make(chan struct{}), make(chan struct{}, 1), true
	block, entered := f.block, f.entered
	f.mu.Unlock()
	var unblock sync.Once
	defer unblock.Do(func() { close(block) })
	record := Record{Kind: "k", ID: "x", Payload: make([]byte, 32)}
	first, err := l.AppendWithClass(context.Background(), record, Data)
	if err != nil {
		t.Fatal(err)
	}
	// The second record cannot fit the first group and becomes held while its
	// Sync blocks. A third request remains in the queue behind that held record.
	held, err := l.AppendWithClass(context.Background(), record, Control)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	queued, err := l.AppendWithClass(context.Background(), record, Control)
	if err != nil {
		t.Fatal(err)
	}
	if usage := l.Usage(); usage.ReservedBytes != 666 || usage.QueuedRecords != 3 {
		t.Fatalf("held reservation lost: %+v", usage)
	}
	unblock.Do(func() { close(block) })
	if result := <-first; !errors.Is(result.Err, ErrIndeterminate) {
		t.Fatalf("active write outcome: %v", result.Err)
	}
	for _, future := range []<-chan Result{held, queued} {
		if result := <-future; !errors.Is(result.Err, ErrNotWritten) || errors.Is(result.Err, ErrIndeterminate) {
			t.Fatalf("unsent outcome: %v", result.Err)
		}
	}
	_ = l.Close()
	if usage := l.Usage(); usage.ReservedBytes != 0 || usage.QueuedRecords != 0 || !usage.Stopped || usage.ControlAvailableBytes != 0 {
		t.Fatalf("failed group leaked/doubly released reservations: %+v", usage)
	}
}

func TestCancellationAndCloseKeepReservationsUntilAcceptedWorkFinishes(t *testing.T) {
	l, f, _ := openTestLog(t, Options{MaxBatchBytes: 256, MaxBatchRecords: 1, MaxLogBytes: 1024, MaxDataBytes: 512, ControlReserveBytes: 512})
	f.mu.Lock()
	f.block, f.entered = make(chan struct{}), make(chan struct{}, 1)
	block, entered := f.block, f.entered
	f.mu.Unlock()
	var unblock sync.Once
	defer unblock.Do(func() { close(block) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	record := Record{Kind: "k", ID: "x", Payload: make([]byte, 32)}
	first, err := l.AppendWithClass(ctx, record, Data)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	second, err := l.AppendWithClass(ctx, record, Control)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- l.Close() }()
	select {
	case err := <-done:
		t.Fatalf("Close abandoned blocked Sync: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if usage := l.Usage(); usage.ReservedBytes != 444 || usage.QueuedRecords != 2 {
		t.Fatalf("cancel/close freed admitted capacity early: %+v", usage)
	}
	unblock.Do(func() { close(block) })
	for _, future := range []<-chan Result{first, second} {
		if result := <-future; result.Err != nil {
			t.Fatal(result.Err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if usage := l.Usage(); usage.DurableBytes != 444 || usage.ReservedBytes != 0 || usage.QueuedRecords != 0 {
		t.Fatalf("drained capacity: %+v", usage)
	}
}
