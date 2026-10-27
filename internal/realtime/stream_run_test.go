package realtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type streamRunWriter struct {
	mu           sync.Mutex
	completed    chan string
	failBodyOnce bool
}

func (w *streamRunWriter) WriteBody(_ context.Context, id string, _ streamlog.Segment) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failBodyOnce {
		w.failBodyOnce = false
		return errors.New("temporary archive failure")
	}
	select {
	case w.completed <- id:
	default:
	}
	return nil
}

func TestRunStreamReportsTransientSinkFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(streamSuricataLine), 0o600); err != nil {
		t.Fatal(err)
	}
	j := startStreamFixture(t, path, 0)
	w := &streamRunWriter{completed: make(chan string, 1), failBodyOnce: true}
	errorsSeen := make(chan error, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunStream(ctx, j, w, StreamRunOptions{Capture: Options{SensorID: "sensor-a", Sources: []Source{{Kind: "suricata", Path: path}}, PollInterval: 10 * time.Millisecond, StoreTimeout: time.Second}, OnSourceError: func(_ Source, err error) {
			select {
			case errorsSeen <- err:
			default:
			}
		}})
	}()
	select {
	case err := <-errorsSeen:
		if err == nil {
			t.Fatal("empty transient failure")
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("transient failure was silently retried")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunStreamDrainOnlyFinalizesSegmentWithoutSinkLanes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.jsonl")
	if err := os.WriteFile(path, []byte("# header\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "suricata", Path: path}
	fileID := fileIdentity(path, info)
	raw := []byte("# header\n")
	sum := sha256.Sum256(raw)
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh", Source: source.Kind, Path: path, FileID: fileID, ParserVersion: "v1"}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(streamlog.Segment{
		Epoch: "fresh", Source: source.Kind, SourcePath: path, FileID: fileID,
		PreviousFileID: fileID, StartOffset: 0, EndOffset: int64(info.Size()),
		ParserVersion: "v1", ArchiveMonth: time.Now().UTC().Format("200601"),
		Raw: raw, RawSHA256: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(source.Kind, path, id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := RunStream(ctx, j, &streamRunWriter{}, StreamRunOptions{
		Capture:   Options{SensorID: "sensor-a", Sources: []Source{source}, PollInterval: 10 * time.Millisecond, StoreTimeout: time.Second},
		DrainOnly: true,
	}); err != nil {
		t.Fatal(err)
	}
	ids, err := j.PendingSegments()
	if err != nil || len(ids) != 0 {
		t.Fatalf("segment without sink work was not finalized: %v %v", ids, err)
	}
}

func TestHoldSmallZeekBindingBatchStopsAtBoundAndDrainsBacklog(t *testing.T) {
	start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	var first time.Time
	if !holdSmallZeekBindingBatch(2048, &first, start) || !first.Equal(start) {
		t.Fatal("small new input should start a bounded coalescing interval")
	}
	if !holdSmallZeekBindingBatch(8192, &first, start.Add(time.Second)) {
		t.Fatal("small input should still be coalesced before two seconds")
	}
	if holdSmallZeekBindingBatch(8192, &first, start.Add(2*time.Second)) {
		t.Fatal("small input was held beyond two seconds")
	}
	if holdSmallZeekBindingBatch(16<<10, &first, start.Add(3*time.Second)) || !first.IsZero() {
		t.Fatal("full backlog must drain immediately")
	}
	if holdSmallZeekBindingBatch(0, &first, start.Add(4*time.Second)) || !first.IsZero() {
		t.Fatal("idle source must clear the coalescing interval")
	}
}
func (w *streamRunWriter) ReconcileBody(context.Context, string, streamlog.Segment) error { return nil }
func (w *streamRunWriter) WriteSearch(context.Context, string, streamlog.Segment) error   { return nil }
func (w *streamRunWriter) ReconcileSearch(context.Context, string, streamlog.Segment) error {
	return nil
}
func (w *streamRunWriter) Project(_ context.Context, id string, _ streamlog.Segment) error {
	return nil
}
func (w *streamRunWriter) ReconcileProjection(context.Context, string, streamlog.Segment) error {
	return nil
}

type projectionAheadWriter struct {
	streamRunWriter
	firstID   string
	unblock   chan struct{}
	projected chan string
}

type parallelArchiveWriter struct {
	streamRunWriter
	firstID  string
	unblock  chan struct{}
	started  chan string
	searched chan string
}

func (w *parallelArchiveWriter) WriteBody(ctx context.Context, id string, _ streamlog.Segment) error {
	w.started <- id
	if id != w.firstID {
		return nil
	}
	select {
	case <-w.unblock:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *parallelArchiveWriter) WriteSearch(_ context.Context, id string, _ streamlog.Segment) error {
	w.searched <- id
	return nil
}

func TestRunStreamArchivesLaterSegmentWhileEarlierArchiveWaits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.jsonl")
	if err := os.WriteFile(path, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	fileID := fileIdentity(path, info)
	j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "suricata", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh", Source: source.Kind, Path: path, FileID: fileID, Offset: 0, ParserVersion: "v1"}); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for index, raw := range [][]byte{[]byte("one\n"), []byte("two\n")} {
		start := int64(index * 4)
		sum := sha256.Sum256(raw)
		id, err := j.Append(streamlog.Segment{
			Epoch: "fresh", Source: source.Kind, SourcePath: path, FileID: fileID,
			PreviousFileID: fileID, PreviousOffset: start, StartOffset: start, EndOffset: start + int64(len(raw)),
			ParserVersion: "v1", RawSHA256: hex.EncodeToString(sum[:]), Raw: raw,
			ArchiveMonth: time.Now().UTC().Format("200601"), AcceptedAt: time.Now().UTC(),
			Events: []normalized.Event{{EventID: string(raw), Type: "discovery"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := j.CommitSource(source.Kind, path, id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	w := &parallelArchiveWriter{firstID: ids[0], unblock: make(chan struct{}), started: make(chan string, 2), searched: make(chan string, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	defer func() { cancel(); <-done }()
	go func() {
		done <- RunStream(ctx, j, w, StreamRunOptions{
			Capture:            Options{SensorID: "sensor-a", Sources: []Source{source}, PollInterval: 10 * time.Millisecond, StoreTimeout: time.Second},
			MaxPendingSegments: 2, ArchiveWorkers: 2, SearchWorkers: 2,
		})
	}()
	seen := make(map[string]bool, len(ids))
	for range ids {
		select {
		case got := <-w.started:
			seen[got] = true
		case <-time.After(500 * time.Millisecond):
			t.Fatal("second archive waited for the first segment")
		}
	}
	if !seen[ids[0]] || !seen[ids[1]] {
		t.Fatalf("both archives were not started: %+v", seen)
	}
	select {
	case got := <-w.searched:
		if got != ids[1] {
			t.Fatalf("search advanced past unarchived body: %s", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("second search waited for the first archive")
	}
	close(w.unblock)
}

func TestStreamRunOffersEarlyDHCPSource(t *testing.T) {
	for _, kind := range []string{"device-signals", "shared-device-signals", "zeek-dhcp-binding"} {
		if !streamSourceOffersEarlyLanes(kind) {
			t.Fatalf("durable source %s still waits for the cursor before sinks", kind)
		}
	}
	if streamSourceOffersEarlyLanes("suricata") {
		t.Fatal("unverified source was offered before cursor commit")
	}
}

type blockedEarlyDHCPWriter struct {
	streamRunWriter
	started chan string
	release chan struct{}
}

func (w *blockedEarlyDHCPWriter) WriteBody(ctx context.Context, id string, _ streamlog.Segment) error {
	select {
	case w.started <- id:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-w.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestRunStreamDHCPUsesEarlySourceDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_dhcp_binding.log")
	line := []byte(`{"ts":1792890000,"uid":"C1","xid":707,"capture_vlan":"42","mac":"02:00:00:00:00:10","assigned_addr":"192.0.2.82","msg_types":"ACK"}` + "\n")
	raw := make([]byte, 0, len(line)*150)
	for range 150 {
		raw = append(raw, line...)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-binding", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), ParserVersion: "zeek-dhcp-binding-v1"}); err != nil {
		t.Fatal(err)
	}
	w := &blockedEarlyDHCPWriter{started: make(chan string, 1), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunStream(ctx, j, w, StreamRunOptions{Capture: Options{SensorID: "sensor-a", Sources: []Source{source}, PollInterval: 10 * time.Millisecond, StoreTimeout: time.Second}, MaxPendingSegments: 2})
	}()
	var id string
	select {
	case id = <-w.started:
	case err := <-done:
		cancel()
		t.Fatalf("DHCP stream stopped before body processing: %v", err)
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("DHCP body lane was not started")
	}
	state, err := j.Load(id)
	if err != nil || !state.Segment.EarlyProcessing || !state.Segment.SourceBackedRaw {
		cancel()
		t.Fatalf("running DHCP source missed early descriptor path: %+v %v", state, err)
	}
	close(w.release)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func (w *projectionAheadWriter) WriteBody(ctx context.Context, id string, _ streamlog.Segment) error {
	if id == w.firstID {
		select {
		case <-w.unblock:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (w *projectionAheadWriter) Project(_ context.Context, id string, _ streamlog.Segment) error {
	w.projected <- id
	return nil
}

func TestRunStreamProjectsNextSegmentWhileArchiveIsBlocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.jsonl")
	if err := os.WriteFile(path, []byte("one\ntwo\ntri\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	fileID := fileIdentity(path, info)
	j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "suricata", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh", Source: source.Kind, Path: path, FileID: fileID, Offset: 0, ParserVersion: "v1"}); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for index, raw := range [][]byte{[]byte("one\n"), []byte("two\n"), []byte("tri\n")} {
		start := int64(index * 4)
		sum := sha256.Sum256(raw)
		id, err := j.Append(streamlog.Segment{
			Epoch: "fresh", Source: source.Kind, SourcePath: path, FileID: fileID,
			PreviousFileID: fileID, PreviousOffset: start, StartOffset: start, EndOffset: start + int64(len(raw)),
			ParserVersion: "v1", RawSHA256: hex.EncodeToString(sum[:]), Raw: raw,
			ArchiveMonth: time.Now().UTC().Format("200601"), AcceptedAt: time.Now().UTC(),
			NeedsProjection: true, Events: []normalized.Event{{EventID: string(raw), Type: "discovery"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := j.CommitSource(source.Kind, path, id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	w := &projectionAheadWriter{firstID: ids[0], unblock: make(chan struct{}), projected: make(chan string, 3)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	t.Cleanup(func() {
		cancel()
		<-done
	})
	go func() {
		done <- RunStream(ctx, j, w, StreamRunOptions{
			Capture:            Options{SensorID: "sensor-a", Sources: []Source{source}, PollInterval: 10 * time.Millisecond, StoreTimeout: time.Second},
			MaxPendingSegments: 2,
		})
	}()
	for _, want := range ids[:2] {
		select {
		case got := <-w.projected:
			if got != want {
				t.Fatalf("projection order: got %s want %s", got, want)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("projection waited for a different segment's archive")
		}
	}
	select {
	case <-w.projected:
		t.Fatal("third segment passed the two-segment in-flight bound")
	case <-time.After(100 * time.Millisecond):
	}
	close(w.unblock)
	select {
	case got := <-w.projected:
		if got != ids[2] {
			t.Fatalf("projection order after archive release: got %s want %s", got, ids[2])
		}
	case <-time.After(time.Second):
		t.Fatal("third segment did not advance after finalization")
	}
}

func TestRunStreamKeepsHealthySourceWhenAnotherIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.jsonl")
	goodPath := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(badPath, []byte(`{"schema_version":"v1","event_id":"bad","type":"risk"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goodPath, []byte(streamSuricataLine), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []Source{{Kind: "device-signals", Path: badPath}, {Kind: "suricata", Path: goodPath}} {
		info, err := os.Stat(source.Path)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh", Source: source.Kind, Path: source.Path, FileID: fileIdentity(source.Path, info), Offset: 0, ParserVersion: "v1"}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &streamRunWriter{completed: make(chan string, 1)}
	errorsSeen := make(chan error, 2)
	done := make(chan error, 1)
	go func() {
		done <- RunStream(ctx, j, w, StreamRunOptions{Capture: Options{SensorID: "sensor-a", Sources: []Source{{Kind: "device-signals", Path: badPath}, {Kind: "suricata", Path: goodPath}}, PollInterval: 10 * time.Millisecond, StoreTimeout: time.Second}, OnSourceError: func(_ Source, err error) {
			select {
			case errorsSeen <- err:
			default:
			}
		}})
	}()
	select {
	case <-w.completed:
	case err := <-done:
		t.Fatalf("healthy source stopped: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("healthy source was blocked by quarantined source")
	}
	select {
	case err := <-errorsSeen:
		if !errors.Is(err, streamlog.ErrQuarantined) {
			t.Fatalf("unexpected source error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("quarantined source was not reported")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(goodPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(streamSuricataLine); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() {
		done2 <- RunStream(ctx2, j, w, StreamRunOptions{Capture: Options{SensorID: "sensor-a", Sources: []Source{{Kind: "device-signals", Path: badPath}, {Kind: "suricata", Path: goodPath}}, PollInterval: 10 * time.Millisecond, StoreTimeout: time.Second}, OnSourceError: func(_ Source, err error) {
			select {
			case errorsSeen <- err:
			default:
			}
		}})
	}()
	select {
	case <-w.completed:
	case err := <-done2:
		cancel2()
		t.Fatalf("restarted healthy source stopped behind persistent quarantine: %v", err)
	case <-time.After(3 * time.Second):
		cancel2()
		t.Fatal("restarted healthy source was blocked by persistent quarantine")
	}
	cancel2()
	if err := <-done2; err != nil {
		t.Fatal(err)
	}
}

func TestRunStreamRecoversDurableInputBeforeCursorCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	raw := []byte(streamSuricataLine)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	fileID := fileIdentity(path, info)
	j, err := streamlog.Open(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "suricata", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh", Source: source.Kind, Path: path, FileID: fileID, Offset: 0, ParserVersion: "v1"}); err != nil {
		t.Fatal(err)
	}
	events, _, err := normalize(source, raw, 0, "sensor-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := assignStreamPositionKeys(events, source, "fresh", fileID, 0, raw); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	id, err := j.Append(streamlog.Segment{Epoch: "fresh", Source: source.Kind, SourcePath: path, FileID: fileID, PreviousFileID: fileID, PreviousOffset: 0, StartOffset: 0, EndOffset: int64(len(raw)), ParserVersion: "v1", RawSHA256: hex.EncodeToString(sum[:]), Raw: raw, AcceptedAt: time.Now().UTC(), ArchiveMonth: time.Now().UTC().Format("200601"), Events: events})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &streamRunWriter{completed: make(chan string, 1)}
	done := make(chan error, 1)
	go func() {
		done <- RunStream(ctx, j, w, StreamRunOptions{Capture: Options{SensorID: "sensor-a", Sources: []Source{source}, PollInterval: 10 * time.Millisecond, StoreTimeout: time.Second}})
	}()
	select {
	case got := <-w.completed:
		if got != id {
			t.Fatalf("wrong recovered segment: %s", got)
		}
	case err := <-done:
		t.Fatalf("recovery stopped: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("durable input was not recovered")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cursor, err := j.LoadSource(source.Kind, path)
	if err != nil || cursor.LastSegmentID != id || cursor.Offset != int64(len(raw)) {
		t.Fatalf("recovery did not confirm source cursor: %+v %v", cursor, err)
	}
}
