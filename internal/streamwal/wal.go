package streamwal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var (
	ErrBounds        = errors.New("stream WAL budget exceeded")
	ErrCapacity      = errors.New("stream WAL capacity reached")
	ErrQueueCapacity = errors.New("stream WAL queue capacity reached")
	ErrDataCapacity  = errors.New("stream WAL data admission limit reached")
	ErrLogCapacity   = errors.New("stream WAL total byte limit reached")
	ErrWriterOwned   = errors.New("stream WAL already has a writer")
	ErrStopped       = errors.New("stream WAL writer stopped")
	ErrNotWritten    = errors.New("stream WAL append was not written")
	ErrIndeterminate = errors.New("stream WAL append outcome is indeterminate; reopen and reconcile")
	ErrTail          = errors.New("stream WAL has an incomplete uncommitted tail; preserved for recovery")
	ErrCorrupt       = errors.New("stream WAL integrity conflict")
)

const walName = "records.v1.wal"

type Options struct {
	MaxRecordBytes      int // Payload bytes, excluding bounded kind/id and framing.
	MaxBatchBytes       int // Encoded bytes, including frames and the group seal.
	MaxBatchRecords     int
	MaxQueuedBytes      int // Includes admitted records currently being synced.
	MaxQueuedRecords    int
	MaxLogBytes         int64 // Total write ceiling; existing larger logs remain readable.
	MaxDataBytes        int64 // Data high-water mark; zero uses MaxLogBytes-ControlReserveBytes.
	ControlReserveBytes int64 // Zero defaults to min(16 MiB, MaxLogBytes/16); must be below total.
	Linger              time.Duration
	wrapFile            func(*os.File) fileIO // Fault injection, deliberately package-private.
}

func (o Options) normalized() (Options, error) {
	if o.MaxRecordBytes == 0 {
		o.MaxRecordBytes = 4 << 20
	}
	if o.MaxBatchBytes == 0 {
		o.MaxBatchBytes = 8 << 20
	}
	if o.MaxBatchRecords == 0 {
		o.MaxBatchRecords = 128
	}
	if o.MaxQueuedBytes == 0 {
		o.MaxQueuedBytes = 32 << 20
	}
	if o.MaxQueuedRecords == 0 {
		o.MaxQueuedRecords = 256
	}
	if o.MaxLogBytes == 0 {
		o.MaxLogBytes = 1 << 30
	}
	if o.ControlReserveBytes == 0 {
		o.ControlReserveBytes = min(16<<20, o.MaxLogBytes/16)
	}
	if o.MaxDataBytes == 0 {
		o.MaxDataBytes = o.MaxLogBytes - o.ControlReserveBytes
	}
	if o.MaxRecordBytes < 1 || o.MaxRecordBytes > maxRecordBytes || o.MaxBatchBytes < headerSize+6+sealSize || o.MaxBatchBytes > maxBatchBytes ||
		o.MaxBatchRecords < 1 || o.MaxBatchRecords > maxBatchRecords || o.MaxQueuedBytes < headerSize+6 || o.MaxQueuedBytes > 64<<20 ||
		o.MaxQueuedRecords < 1 || o.MaxQueuedRecords > 4096 || o.MaxLogBytes < 1 || o.MaxLogBytes > maxLogBytes ||
		o.ControlReserveBytes < 0 || o.ControlReserveBytes >= o.MaxLogBytes || o.MaxDataBytes < 1 || o.MaxDataBytes > o.MaxLogBytes-o.ControlReserveBytes ||
		o.Linger < 0 || o.Linger > 100*time.Millisecond {
		return o, ErrBounds
	}
	return o, nil
}

type Record struct {
	Kind, ID string
	Payload  []byte
}

// AppendClass selects admission headroom, not a different on-disk format.
// Control is reserved for bounded completion/recovery records, never event bodies.
type AppendClass uint8

const (
	Data AppendClass = iota
	Control
)

// Usage is a consistent admission snapshot. ReservedBytes includes all queued
// and syncing records with one worst-case seal each. Available bytes are zero
// once closed/stopped; they are logical budgets, not free filesystem space.
type Usage struct {
	DurableBytes          int64
	ReservedBytes         int64
	QueuedRecords         int
	DataAvailableBytes    int64
	ControlAvailableBytes int64
	Stopped               bool
}

// Receipt is returned only after Sync succeeds, or replayed after Open has
// re-synced a fully verified log. Its private proofs bind Read to those bytes.
type Receipt struct {
	LSN        uint64
	Offset     int64
	Length     int
	digest     [32]byte
	sealOffset int64
	sealDigest [32]byte
}

type Result struct {
	Receipt Receipt
	Err     error
}
type Entry struct {
	Receipt Receipt
	Record  Record
}

// Recovery describes validated, sealed groups. Inspect alone is read-only and
// does not establish a new durability barrier after an earlier Sync error.
type Recovery struct {
	LastLSN         uint64
	EndOffset       int64
	Records, Groups uint64
	TailBytes       int64
	prefixDigest    [32]byte
}

// Position identifies a fully sealed v1 prefix. It is a content proof for the
// current single file, not a cross-generation locator or proof that a caller
// has folded every receipt into its own state.
type Position struct {
	FormatVersion uint8
	LastLSN       uint64
	EndOffset     int64
	PrefixSHA256  [32]byte
}

type fileIO interface {
	io.Writer
	io.ReaderAt
	Sync() error
	Stat() (os.FileInfo, error)
	Close() error
}

type request struct {
	record        Record
	bytes         int
	reservedBytes int64
	result        chan Result
}

type Log struct {
	file                       fileIO
	lease                      *os.File
	opts                       Options
	queue                      chan *request
	done                       chan struct{}
	mu                         sync.Mutex
	closed                     bool
	terminal                   error
	queuedBytes, queuedRecords int
	reservedBytes              int64
	ioMu                       sync.RWMutex
	recovery                   Recovery
	closeOnce                  sync.Once
	closeErr                   error
}

// Open acquires an exclusive writer lease and validates every existing group.
// Incomplete tails are never truncated and prevent writable reopening. A
// successful recovery Sync seals complete groups whose prior result was lost.
func Open(dir string, options Options) (*Log, error) {
	o, err := options.normalized()
	if err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, errors.New("stream WAL directory is required")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lease, err := os.OpenFile(filepath.Join(dir, ".writer.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lease.Close()
		return nil, fmt.Errorf("%w: %v", ErrWriterOwned, err)
	}
	cleanup := func() { _ = syscall.Flock(int(lease.Fd()), syscall.LOCK_UN); _ = lease.Close() }
	f, err := os.OpenFile(filepath.Join(dir, walName), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		cleanup()
		return nil, err
	}
	var file fileIO = f
	if o.wrapFile != nil {
		file = o.wrapFile(f)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		cleanup()
		return nil, err
	}
	recovery, err := scan(file, info.Size(), o, nil)
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = syncDirectoryAncestry(dir, syncDirectory)
	}
	if err != nil {
		file.Close()
		cleanup()
		return nil, err
	}
	l := &Log{file: file, lease: lease, opts: o, queue: make(chan *request, o.MaxQueuedRecords), done: make(chan struct{}), recovery: recovery}
	go l.run()
	return l, nil
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Sync the directory and its ancestors, including on retry. MkdirAll can have
// succeeded during an earlier failed Open; existence alone does not prove that
// those directory entries survived a durability barrier.
func syncDirectoryAncestry(dir string, sync func(string) error) error {
	for {
		if err := sync(dir); err != nil {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// Inspect validates a read-only snapshot. Call against a stopped writer for a
// stable recovery assessment; concurrent appends can appear as incomplete tails.
func Inspect(dir string, options Options) (Recovery, error) {
	o, err := options.normalized()
	if err != nil {
		return Recovery{}, err
	}
	f, err := os.Open(filepath.Join(dir, walName))
	if err != nil {
		return Recovery{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Recovery{}, err
	}
	return scan(f, info.Size(), o, nil)
}

// Append admits a Data record. Use AppendWithClass for completion records.
func (l *Log) Append(ctx context.Context, record Record) (<-chan Result, error) {
	return l.AppendWithClass(ctx, record, Data)
}

// AppendWithClass reserves queue and disk budgets before copying the payload.
// Capacity rejection returns ErrNotWritten plus ErrCapacity and its specific
// queue/data/total cause; no result channel is returned and the writer stays usable.
// Once admitted the caller must consume the result, even if its context later
// expires. IDs are opaque; business-level duplicate/conflict reconciliation
// belongs to callers.
func (l *Log) AppendWithClass(ctx context.Context, record Record, class AppendClass) (<-chan Result, error) {
	if class != Data && class != Control {
		return nil, ErrBounds
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	size, err := recordSize(record, l.opts)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.terminal != nil {
		return nil, ErrStopped
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if l.queuedRecords >= l.opts.MaxQueuedRecords || size > l.opts.MaxQueuedBytes-l.queuedBytes {
		return nil, errors.Join(ErrNotWritten, ErrCapacity, ErrQueueCapacity)
	}
	reserved := int64(size + sealSize)
	used := l.recovery.EndOffset + l.reservedBytes
	if reserved > l.opts.MaxLogBytes-used {
		return nil, errors.Join(ErrNotWritten, ErrCapacity, ErrLogCapacity)
	}
	if class == Data && reserved > l.opts.MaxDataBytes-used {
		return nil, errors.Join(ErrNotWritten, ErrCapacity, ErrDataCapacity)
	}
	copy := record
	copy.Payload = append([]byte(nil), record.Payload...)
	req := &request{record: copy, bytes: size, reservedBytes: reserved, result: make(chan Result, 1)}
	l.queuedRecords++
	l.queuedBytes += size
	l.reservedBytes += reserved
	l.queue <- req // The channel has at least as many slots as the admission cap.
	return req.result, nil
}

func (l *Log) complete(req *request, result Result) {
	l.mu.Lock()
	l.queuedRecords--
	l.queuedBytes -= req.bytes
	l.reservedBytes -= req.reservedBytes
	req.reservedBytes = 0
	l.mu.Unlock()
	req.result <- result
	close(req.result)
}

func (l *Log) stop(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.terminal = err
	if !l.closed {
		l.closed = true
		close(l.queue)
	}
}

func (l *Log) run() {
	defer close(l.done)
	var held *request
	for {
		first := held
		held = nil
		if first == nil {
			var ok bool
			first, ok = <-l.queue
			if !ok {
				return
			}
		}
		batch := []*request{first}
		size := first.bytes + sealSize
		var timer *time.Timer
		var timeout <-chan time.Time
		if l.opts.Linger > 0 {
			timer = time.NewTimer(l.opts.Linger)
			timeout = timer.C
		}
		closed := false
	gather:
		for len(batch) < l.opts.MaxBatchRecords {
			var next *request
			var ok bool
			if timeout == nil {
				select {
				case next, ok = <-l.queue:
				default:
					break gather
				}
			} else {
				select {
				case next, ok = <-l.queue:
				case <-timeout:
					break gather
				}
			}
			if !ok {
				closed = true
				break
			}
			if next.bytes > l.opts.MaxBatchBytes-size {
				held = next
				break
			}
			batch = append(batch, next)
			size += next.bytes
		}
		if timer != nil {
			timer.Stop()
		}
		receipts, err := l.commit(batch, size)
		if err != nil {
			l.stop(err)
			for _, req := range batch {
				l.complete(req, Result{Err: err})
			}
			if held != nil {
				l.complete(held, Result{Err: errors.Join(ErrNotWritten, ErrStopped)})
				held = nil
			}
			for req := range l.queue {
				l.complete(req, Result{Err: errors.Join(ErrNotWritten, ErrStopped)})
			}
			return
		}
		for i, req := range batch {
			l.complete(req, Result{Receipt: receipts[i]})
		}
		if closed {
			return
		}
	}
}

func (l *Log) commit(batch []*request, size int) ([]Receipt, error) {
	// Appends never alter the committed prefix. Hold only the file-lifetime
	// read lock so existing durable records remain readable during a slow Sync.
	l.ioMu.RLock()
	defer l.ioMu.RUnlock()
	recovery := l.durableSnapshot()
	info, err := l.file.Stat()
	if err != nil {
		return nil, errors.Join(ErrNotWritten, err)
	}
	if info.Size() != recovery.EndOffset {
		return nil, errors.Join(ErrNotWritten, ErrCorrupt)
	}
	if int64(size) > l.opts.MaxLogBytes-recovery.EndOffset {
		return nil, errors.Join(ErrNotWritten, ErrCapacity)
	}
	encoded, receipts := encodeGroup(batch, recovery.LastLSN+1, recovery.EndOffset)
	if len(encoded) != size {
		return nil, errors.Join(ErrNotWritten, ErrCorrupt)
	}
	n, err := l.file.Write(encoded)
	if err == nil && n != len(encoded) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = l.file.Sync()
	}
	if err != nil {
		return nil, errors.Join(ErrIndeterminate, err)
	}
	l.mu.Lock()
	l.recovery.LastLSN += uint64(len(batch))
	l.recovery.Records += uint64(len(batch))
	l.recovery.Groups++
	l.recovery.EndOffset += int64(len(encoded))
	l.recovery.prefixDigest = chainSeal(l.recovery.prefixDigest, receipts[0].sealDigest)
	// Convert all group reservations to the actual durable bytes atomically.
	// complete releases memory/queue counts later, but must not charge these
	// records twice or expose a window in which neither budget accounts for them.
	for _, req := range batch {
		l.reservedBytes -= req.reservedBytes
		req.reservedBytes = 0
	}
	l.mu.Unlock()
	return receipts, nil
}

func (l *Log) durableSnapshot() Recovery {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.recovery
}

// DurablePosition reports the last Sync-confirmed v1 group boundary. Callers
// must first exclude in-flight adapter mutations before using it for a
// checkpoint; a WAL receipt can precede its in-memory state fold.
func (l *Log) DurablePosition() Position {
	r := l.durableSnapshot()
	return Position{FormatVersion: 1, LastLSN: r.LastLSN, EndOffset: r.EndOffset, PrefixSHA256: r.prefixDigest}
}

// VerifyPosition replays a prefix from the current v1 file to check its
// content proof. It is intended for maintenance, not the append hot path.
func (l *Log) VerifyPosition(p Position) error {
	l.ioMu.RLock()
	defer l.ioMu.RUnlock()
	if p.FormatVersion != 1 || p.EndOffset < 0 || p.EndOffset > l.durableSnapshot().EndOffset {
		return ErrCorrupt
	}
	r, err := scan(l.file, p.EndOffset, l.opts, nil)
	if err != nil {
		return err
	}
	if r.LastLSN != p.LastLSN || r.EndOffset != p.EndOffset || r.prefixDigest != p.PrefixSHA256 {
		return ErrCorrupt
	}
	return nil
}

// Usage reports current logical headroom without changing admission or disk state.
func (l *Log) Usage() Usage {
	l.mu.Lock()
	defer l.mu.Unlock()
	u := Usage{DurableBytes: l.recovery.EndOffset, ReservedBytes: l.reservedBytes, QueuedRecords: l.queuedRecords, Stopped: l.closed || l.terminal != nil}
	if !u.Stopped {
		used := u.DurableBytes + u.ReservedBytes
		u.DataAvailableBytes = max(l.opts.MaxDataBytes-used, 0)
		u.ControlAvailableBytes = max(l.opts.MaxLogBytes-used, 0)
	}
	return u
}

// Replay visits a snapshot of the durable prefix and decodes at most one group
// at a time, without waiting for later appends. Use it for startup recovery, not
// request-path full-log scans. Visitor must not reenter this Log.
func (l *Log) Replay(visit func(Entry) error) error {
	l.ioMu.RLock()
	defer l.ioMu.RUnlock()
	_, err := scan(l.file, l.durableSnapshot().EndOffset, l.opts, visit)
	return err
}

// Read verifies exactly the recorded frame and its group seal, without reading
// unrelated event bodies. The receipt's private proofs come from commit/replay.
func (l *Log) Read(receipt Receipt) (Record, error) {
	l.ioMu.RLock()
	defer l.ioMu.RUnlock()
	end := l.durableSnapshot().EndOffset
	if receipt.LSN == 0 || receipt.Offset < 0 || receipt.Offset >= receipt.sealOffset || receipt.sealOffset >= end {
		return Record{}, ErrCorrupt
	}
	frame, err := readFrame(l.file, end, receipt.Offset)
	if err != nil {
		return Record{}, err
	}
	if frame.kind != dataFrame || frame.lsn != receipt.LSN || frame.length != receipt.Length || frame.digest != receipt.digest {
		return Record{}, ErrCorrupt
	}
	seal, err := readFrame(l.file, end, receipt.sealOffset)
	if err != nil {
		return Record{}, err
	}
	if seal.kind != sealFrame || seal.digest != receipt.sealDigest {
		return Record{}, ErrCorrupt
	}
	return decodeRecord(frame.payload)
}

// Close drains admitted appends, then closes the file and releases the writer
// lease. It returns any terminal write error; it never retries an unknown write.
func (l *Log) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		if !l.closed {
			l.closed = true
			close(l.queue)
		}
		l.mu.Unlock()
		<-l.done
		l.mu.Lock()
		l.closeErr = l.terminal
		l.mu.Unlock()
		l.ioMu.Lock()
		l.closeErr = errors.Join(l.closeErr, l.file.Close())
		l.ioMu.Unlock()
		l.closeErr = errors.Join(l.closeErr, syscall.Flock(int(l.lease.Fd()), syscall.LOCK_UN), l.lease.Close())
	})
	return l.closeErr
}
