package streamwal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type faultFile struct {
	*os.File
	mu        sync.Mutex
	block     chan struct{}
	entered   chan struct{}
	failSync  bool
	failWrite bool
	short     bool
	syncs     int
}

func (f *faultFile) Sync() error {
	f.mu.Lock()
	f.syncs++
	block, entered, fail := f.block, f.entered, f.failSync
	f.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if block != nil {
		<-block
	}
	if fail {
		return errors.New("injected sync error")
	}
	return f.File.Sync()
}

func (f *faultFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	short, fail := f.short, f.failWrite
	f.mu.Unlock()
	if fail {
		return 0, errors.New("injected write error")
	}
	if short {
		return f.File.Write(p[:len(p)/2])
	}
	return f.File.Write(p)
}

func openTestLog(t *testing.T, opts Options) (*Log, *faultFile, string) {
	t.Helper()
	dir := t.TempDir()
	var fault *faultFile
	opts.wrapFile = func(f *os.File) fileIO { fault = &faultFile{File: f}; return fault }
	l, err := Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, fault, dir
}

func submit(t *testing.T, l *Log, id string) <-chan Result {
	t.Helper()
	future, err := l.Append(context.Background(), Record{Kind: "accept", ID: id, Payload: []byte("exact evidence")})
	if err != nil {
		t.Fatal(err)
	}
	return future
}

func TestGroupReceiptsWaitForSyncAndRecover(t *testing.T) {
	l, f, dir := openTestLog(t, Options{Linger: 30 * time.Millisecond})
	f.mu.Lock()
	f.block = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	block, entered := f.block, f.entered
	baseline := f.syncs
	f.mu.Unlock()
	a, b := submit(t, l, "a"), submit(t, l, "b")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer never synced")
	}
	select {
	case result := <-a:
		t.Fatalf("receipt before sync: %+v", result)
	default:
	}
	close(block)
	ra, rb := <-a, <-b
	if ra.Err != nil || rb.Err != nil || ra.Receipt.LSN != 1 || rb.Receipt.LSN != 2 {
		t.Fatalf("receipts: %+v %+v", ra, rb)
	}
	f.mu.Lock()
	calls := f.syncs - baseline
	f.mu.Unlock()
	if calls != 1 {
		t.Fatalf("group required %d syncs", calls)
	}
	r, err := l.Read(ra.Receipt)
	if err != nil || string(r.Payload) != "exact evidence" || r.ID != "a" {
		t.Fatalf("read: %+v %v", r, err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var ids []string
	if err := reopened.Replay(func(e Entry) error { ids = append(ids, e.Record.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("replay=%v", ids)
	}
	c := <-submit(t, reopened, "c")
	if c.Err != nil || c.Receipt.LSN != 3 {
		t.Fatalf("next LSN: %+v", c)
	}
}

func TestSyncFailureIsIndeterminateAndRequiresRecovery(t *testing.T) {
	l, f, dir := openTestLog(t, Options{})
	f.mu.Lock()
	f.failSync = true
	f.mu.Unlock()
	r := <-submit(t, l, "ambiguous")
	if !errors.Is(r.Err, ErrIndeterminate) || r.Receipt.LSN != 0 {
		t.Fatalf("sync failure=%+v", r)
	}
	if _, err := l.Append(context.Background(), Record{Kind: "accept", ID: "retry"}); !errors.Is(err, ErrStopped) {
		t.Fatalf("poisoned writer accepted retry: %v", err)
	}
	_ = l.Close()
	reopened, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var n int
	if err := reopened.Replay(func(e Entry) error {
		n++
		if e.Record.ID != "ambiguous" {
			t.Fatal(e.Record.ID)
		}
		return nil
	}); err != nil || n != 1 {
		t.Fatalf("ambiguous sealed result lost: %d %v", n, err)
	}
}

func TestShortWriteRetainsTailAndStops(t *testing.T) {
	l, f, dir := openTestLog(t, Options{})
	f.mu.Lock()
	f.short = true
	f.mu.Unlock()
	r := <-submit(t, l, "partial")
	if !errors.Is(r.Err, ErrIndeterminate) || !errors.Is(r.Err, io.ErrShortWrite) {
		t.Fatalf("short write=%v", r.Err)
	}
	_ = l.Close()
	before, err := os.ReadFile(filepath.Join(dir, walName))
	if err != nil || len(before) == 0 {
		t.Fatalf("tail missing: %v", err)
	}
	info, err := Inspect(dir, Options{})
	if !errors.Is(err, ErrTail) || info.TailBytes == 0 || info.Records != 0 {
		t.Fatalf("inspect=%+v %v", info, err)
	}
	if _, err := Open(dir, Options{}); !errors.Is(err, ErrTail) {
		t.Fatalf("truncated tail reopened writable: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, walName))
	if string(before) != string(after) {
		t.Fatal("recovery rewrote the unique tail")
	}
}

func TestWriterLeaseAndByteRecordBudgets(t *testing.T) {
	l, f, dir := openTestLog(t, Options{MaxRecordBytes: 32, MaxQueuedRecords: 1, MaxQueuedBytes: 128})
	if second, err := Open(dir, Options{}); !errors.Is(err, ErrWriterOwned) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second writer: %v", err)
	}
	if _, err := l.Append(context.Background(), Record{Kind: "accept", ID: "big", Payload: make([]byte, 33)}); !errors.Is(err, ErrBounds) {
		t.Fatalf("record bound: %v", err)
	}
	f.mu.Lock()
	f.block = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	block, entered := f.block, f.entered
	f.mu.Unlock()
	future := submit(t, l, "first")
	<-entered
	if _, err := l.Append(context.Background(), Record{Kind: "accept", ID: "queued"}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("in-flight admission was not counted: %v", err)
	}
	close(block)
	if result := <-future; result.Err != nil {
		t.Fatal(result.Err)
	}
}

func TestQueueByteBudgetIndependentOfRecordCount(t *testing.T) {
	l, f, _ := openTestLog(t, Options{MaxQueuedRecords: 4, MaxQueuedBytes: 110})
	f.mu.Lock()
	f.block = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	block, entered := f.block, f.entered
	f.mu.Unlock()
	future := submit(t, l, "one")
	<-entered
	if _, err := l.Append(context.Background(), Record{Kind: "accept", ID: "two"}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("queue byte limit ignored: %v", err)
	}
	close(block)
	<-future
}

func TestBatchRecordAndByteBudgets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opts   Options
		groups uint64
	}{{"records", Options{MaxBatchRecords: 2, Linger: 20 * time.Millisecond}, 2}, {"bytes", Options{MaxBatchBytes: 256, Linger: 20 * time.Millisecond}, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			l, _, dir := openTestLog(t, tc.opts)
			a, b, c := submit(t, l, "a"), submit(t, l, "b"), submit(t, l, "c")
			for _, future := range []<-chan Result{a, b, c} {
				if result := <-future; result.Err != nil {
					t.Fatal(result.Err)
				}
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			info, err := Inspect(dir, tc.opts)
			if err != nil || info.Groups != tc.groups || info.Records != 3 {
				t.Fatalf("batch limits: %+v %v", info, err)
			}
		})
	}
}

func TestAdmittedPayloadOwnedAndCancellationDoesNotRetract(t *testing.T) {
	l, f, _ := openTestLog(t, Options{})
	f.mu.Lock()
	f.block = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	block, entered := f.block, f.entered
	f.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	payload := []byte("original")
	future, err := l.Append(ctx, Record{Kind: "accept", ID: "owned", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	copy(payload, "mutated!")
	cancel()
	<-entered
	if _, err := l.Append(ctx, Record{Kind: "accept", ID: "cancelled"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(block)
	result := <-future
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	record, err := l.Read(result.Receipt)
	if err != nil || string(record.Payload) != "original" {
		t.Fatalf("payload mutation: %+v %v", record, err)
	}
}

func TestQueuedUnsentRequestsAreDistinguishedFromUnknownWrite(t *testing.T) {
	l, f, _ := openTestLog(t, Options{MaxBatchRecords: 1})
	f.mu.Lock()
	f.block = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	f.failSync = true
	block, entered := f.block, f.entered
	f.mu.Unlock()
	a := submit(t, l, "sent")
	<-entered
	b := submit(t, l, "not-sent")
	close(block)
	first, second := <-a, <-b
	if !errors.Is(first.Err, ErrIndeterminate) || !errors.Is(second.Err, ErrNotWritten) || errors.Is(second.Err, ErrIndeterminate) {
		t.Fatalf("outcomes: %v / %v", first.Err, second.Err)
	}
}

func TestLogCapacityNeverClaimsAnUnwrittenAppend(t *testing.T) {
	l, _, dir := openTestLog(t, Options{MaxBatchBytes: 256, MaxLogBytes: 256})
	first := <-submit(t, l, "a")
	if first.Err != nil {
		t.Fatal(first.Err)
	}
	second, err := l.Append(context.Background(), Record{Kind: "accept", ID: "b", Payload: []byte("exact evidence")})
	if second != nil || !errors.Is(err, ErrNotWritten) || !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity outcome=%v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("known capacity rejection stopped writer: %v", err)
	}
	info, err := Inspect(dir, Options{MaxBatchBytes: 256, MaxLogBytes: 256})
	if err != nil || info.Records != 1 {
		t.Fatalf("capacity modified committed data: %+v %v", info, err)
	}
}

func TestEveryTruncatedPrefixPublishesOnlySealedGroups(t *testing.T) {
	l, _, dir := openTestLog(t, Options{MaxBatchRecords: 1})
	first := <-submit(t, l, "one")
	second := <-submit(t, l, "two")
	if first.Err != nil || second.Err != nil {
		t.Fatalf("append: %v %v", first.Err, second.Err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, walName))
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := (Options{}).normalized()
	firstEnd := int(first.Receipt.sealOffset) + sealSize
	for cut := 0; cut <= len(raw); cut++ {
		seen := 0
		info, err := scan(bytes.NewReader(raw[:cut]), int64(cut), opts, func(Entry) error { seen++; return nil })
		want := 0
		if cut >= firstEnd {
			want++
		}
		if cut == len(raw) {
			want++
		}
		if seen != want || int(info.Records) != want {
			t.Fatalf("cut %d exposed unsealed frame: %d %+v", cut, seen, info)
		}
		boundary := cut == 0 || cut == firstEnd || cut == len(raw)
		if boundary && err != nil || !boundary && !errors.Is(err, ErrTail) {
			t.Fatalf("cut %d error=%v", cut, err)
		}
	}
}

func TestFrameAndSealCorruptionIsPreservedAndRejected(t *testing.T) {
	for _, mode := range []string{"frame", "seal", "resealed-frame"} {
		t.Run(mode, func(t *testing.T) {
			l, _, dir := openTestLog(t, Options{})
			result := <-submit(t, l, "evidence")
			if result.Err != nil {
				t.Fatal(result.Err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, walName)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "seal" {
				raw[len(raw)-1] ^= 1
			} else if mode == "frame" {
				raw[headerSize+4] ^= 1
			} else {
				frame, err := readFrame(bytes.NewReader(raw), int64(len(raw)), 0)
				if err != nil {
					t.Fatal(err)
				}
				frame.payload[len(frame.payload)-1] ^= 1
				copy(raw, encodeFrame(frame.kind, frame.lsn, frame.payload))
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir, Options{}); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("corruption accepted: %v", err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(raw, after) {
				t.Fatal("corrupt evidence rewritten")
			}
		})
	}
}

func TestReadRejectsBodyChangedAfterReceipt(t *testing.T) {
	l, _, dir := openTestLog(t, Options{})
	result := <-submit(t, l, "evidence")
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	f, err := os.OpenFile(filepath.Join(dir, walName), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteAt([]byte{0}, result.Receipt.Offset+headerSize+4)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Read(result.Receipt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("changed body accepted: %v", err)
	}
}

func TestRecoveryDoesNotApplyNewWriteBudgetsToOldFrames(t *testing.T) {
	l, _, dir := openTestLog(t, Options{Linger: 20 * time.Millisecond})
	a, b := submit(t, l, "old-a"), submit(t, l, "old-b")
	first, second := <-a, <-b
	if first.Err != nil || second.Err != nil {
		t.Fatalf("initial: %v %v", first.Err, second.Err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// These limits admit only a much smaller record, one per future batch.
	// They must not change the on-disk format or invalidate prior commitments.
	limits := Options{MaxRecordBytes: 1, MaxBatchRecords: 1, MaxBatchBytes: 200, MaxQueuedBytes: 80, MaxQueuedRecords: 1}
	reopened, err := Open(dir, limits)
	if err != nil {
		t.Fatalf("valid data rejected after write-budget reduction: %v", err)
	}
	defer reopened.Close()
	count := 0
	if err := reopened.Replay(func(Entry) error { count++; return nil }); err != nil || count != 2 {
		t.Fatalf("replay: %d %v", count, err)
	}
	r, err := reopened.Read(first.Receipt)
	if err != nil || string(r.Payload) != "exact evidence" {
		t.Fatalf("old body no longer readable: %+v %v", r, err)
	}
	if _, err := reopened.Append(context.Background(), Record{Kind: "accept", ID: "new", Payload: []byte("too large")}); !errors.Is(err, ErrBounds) {
		t.Fatalf("new admission ignored lowered bounds: %v", err)
	}
}

func TestAppendRejectsUnexpectedPhysicalEnd(t *testing.T) {
	for _, kind := range []string{"truncate", "append"} {
		t.Run(kind, func(t *testing.T) {
			l, _, dir := openTestLog(t, Options{})
			first := <-submit(t, l, "committed")
			if first.Err != nil {
				t.Fatal(first.Err)
			}
			path := filepath.Join(dir, walName)
			if kind == "truncate" {
				if err := os.Truncate(path, 1); err != nil {
					t.Fatal(err)
				}
			} else {
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write([]byte("foreign tail"))
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			next := <-submit(t, l, "must-not-write")
			if !errors.Is(next.Err, ErrNotWritten) || !errors.Is(next.Err, ErrCorrupt) || next.Receipt.LSN != 0 {
				t.Fatalf("unexpected EOF accepted: %+v", next)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("appended into changed journal")
			}
		})
	}
}

func TestConcurrentAppendAndCloseDrainEveryAdmittedResult(t *testing.T) {
	l, f, dir := openTestLog(t, Options{Linger: time.Millisecond})
	f.mu.Lock()
	f.block = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	block, entered := f.block, f.entered
	f.mu.Unlock()
	first := submit(t, l, "first")
	<-entered
	const producers = 32
	futures := make(chan (<-chan Result), producers)
	var producersDone sync.WaitGroup
	for i := 0; i < producers; i++ {
		producersDone.Add(1)
		go func(id int) {
			defer producersDone.Done()
			future, err := l.Append(context.Background(), Record{Kind: "accept", ID: fmt.Sprintf("id-%d", id)})
			if err != nil {
				t.Error(err)
				return
			}
			futures <- future
		}(i)
	}
	producersDone.Wait()
	close(futures)
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	close(block)
	if result := <-first; result.Err != nil {
		t.Fatal(result.Err)
	}
	seen := map[uint64]bool{1: true}
	for future := range futures {
		result := <-future
		if result.Err != nil || result.Receipt.LSN == 0 || seen[result.Receipt.LSN] {
			t.Fatalf("result=%+v", result)
		}
		seen[result.Receipt.LSN] = true
		if _, ok := <-future; ok {
			t.Fatal("append returned multiple results")
		}
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not drain")
	}
	info, err := Inspect(dir, Options{})
	if err != nil || info.Records != producers+1 || len(seen) != producers+1 {
		t.Fatalf("commits lost: %+v %d %v", info, len(seen), err)
	}
}

func TestDirectoryBarrierIncludesAncestorsAndPropagatesFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new-parent", "new-wal")
	var calls []string
	if err := syncDirectoryAncestry(dir, func(path string) error { calls = append(calls, path); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(calls) < 3 || calls[0] != dir || calls[1] != filepath.Dir(dir) || filepath.Dir(calls[len(calls)-1]) != calls[len(calls)-1] {
		t.Fatalf("incomplete barriers: %v", calls)
	}
	want := errors.New("parent sync failed")
	visited := 0
	if err := syncDirectoryAncestry(dir, func(string) error {
		visited++
		if visited == 2 {
			return want
		}
		return nil
	}); !errors.Is(err, want) || visited != 2 {
		t.Fatalf("directory failure ignored: calls=%d err=%v", visited, err)
	}
}

func TestDurableReadDoesNotWaitForLaterSync(t *testing.T) {
	l, f, _ := openTestLog(t, Options{})
	first := <-submit(t, l, "durable")
	if first.Err != nil {
		t.Fatal(first.Err)
	}
	f.mu.Lock()
	f.block = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	block, entered := f.block, f.entered
	f.mu.Unlock()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(block) }) }
	defer release()
	second := submit(t, l, "still-syncing")
	<-entered
	readDone := make(chan error, 1)
	go func() {
		r, err := l.Read(first.Receipt)
		if err == nil && r.ID != "durable" {
			err = errors.New("wrong durable frame")
		}
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		release()
		<-second
		<-readDone
		t.Fatal("durable prefix read waited for unrelated group sync")
	}
	replayDone := make(chan error, 1)
	go func() {
		count := 0
		err := l.Replay(func(Entry) error { count++; return nil })
		if err == nil && count != 1 {
			err = fmt.Errorf("replay exposed %d records before sync", count)
		}
		replayDone <- err
	}()
	select {
	case err := <-replayDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		release()
		<-second
		<-replayDone
		t.Fatal("durable prefix replay waited for unrelated sync")
	}
	release()
	if result := <-second; result.Err != nil {
		t.Fatal(result.Err)
	}
}
