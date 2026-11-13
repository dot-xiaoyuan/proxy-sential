package realtime

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/streamlog"
)

// A recovery directory holds hard links to a single snapshot of numbered
// rotations and, optionally, ttl-live-*.jsonl from the same source.
const deviceSignalRecoveryDirEnv = "PROXY_SENTINEL_DEVICE_SIGNAL_RECOVERY_DIR"

type signalFile struct {
	path       string
	info       os.FileInfo
	id         string
	legacyID   string // Allows a proved old cursor to finish before birth-aware rotation.
	ordinal    int    // 1 is newest rotation, 0 is protected live, -1 is current.
	chainSeq   int    // -1 outside the protected compressed successor chain.
	protected  bool
	compressed bool
}

func readDeviceSignalChunk(path string, cursor streamlog.SourceCursor, maxBytes int64) (sourceChunk, error) {
	if maxBytes <= 0 || maxBytes > streamReadLimit {
		return sourceChunk{}, fmt.Errorf("invalid device signal read bound")
	}
	files, err := deviceSignalFiles(path)
	if err != nil {
		return sourceChunk{}, err
	}
	matches := matchingSignalCursorFiles(path, files, cursor, probeSignalGzipTail)
	file, ok := uniqueSignalMatch(matches)
	if !ok {
		return sourceChunk{}, ErrStreamSourceGap
	}
	var read sourceChunk
	if file.compressed {
		read, err = readSignalGzip(path, file, cursor, maxBytes)
	} else {
		clearSignalGzip(path)
		read, err = readSignalRaw(path, file, cursor, maxBytes)
	}
	if err != nil {
		return sourceChunk{}, err
	}
	if len(read.data) > 0 || file.path == path {
		return read, nil
	}
	if !file.compressed && file.info.Size() != cursor.Offset {
		return sourceChunk{}, ErrStreamSourceGap
	}
	if file.protected && file.ordinal == 0 {
		for _, active := range files {
			if active.path == path && os.SameFile(active.info, file.info) {
				return read, nil // The protected live inode may still grow.
			}
		}
	}
	next, err := nextSignalFile(path, files, file)
	if err != nil {
		return sourceChunk{}, err
	}
	if next.compressed {
		read, err = readSignalGzip(path, next, streamlog.SourceCursor{FileID: next.id}, maxBytes)
	} else {
		clearSignalGzip(path)
		read, err = readSignalRaw(path, next, streamlog.SourceCursor{FileID: next.id}, maxBytes)
	}
	if err != nil || len(read.data) == 0 && next.path != path {
		return sourceChunk{}, ErrStreamSourceGap
	}
	read.verifiedRotation = true
	return read, nil
}

func matchingSignalCursorFiles(path string, files []signalFile, cursor streamlog.SourceCursor, probe func(string, streamlog.SourceCursor) bool) []signalFile {
	var matches []signalFile
	for _, file := range files {
		if file.id != cursor.FileID && !(os.Getenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID") == "true" &&
			cursor.Offset > 0 && validSignalTail(cursor) && file.legacyID == cursor.FileID) {
			continue
		}
		if file.compressed && !signalGzipCursorMatches(path, file, cursor) {
			continue
		}
		if !file.compressed && !signalRawCursorMatches(file, cursor) {
			continue
		}
		matches = append(matches, file)
	}
	// The first archive still carries the old, uncompressed FileID. Once its
	// committed tail has been proved and the inflater opened, reuse that proof
	// while the cursor advances instead of re-inflating the entire prefix of
	// every archive on every segment.
	if len(matches) == 0 {
		signalGzipState.Lock()
		cached := signalGzipState.bySource[path]
		if cacheSupportsCursor(cached, cursor) {
			for _, file := range files {
				if file.compressed && os.SameFile(file.info, cached.info) {
					matches = append(matches, file)
				}
			}
		}
		signalGzipState.Unlock()
	}
	// Compression changes inode. A unique committed tail proves that the
	// first gzip archive contains the old cursor's original byte stream.
	if len(matches) == 0 && cursor.Offset > 0 && validSignalTail(cursor) {
		for _, file := range files {
			if file.compressed && file.id != cursor.FileID && probe(file.path, cursor) {
				matches = append(matches, file)
			}
		}
	}
	return matches
}

func deviceSignalFiles(path string) ([]signalFile, error) {
	var out []signalFile
	add := func(name string, protected bool) error {
		info, err := os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		ordinal, compressed, valid := signalFileOrdinal(path, name, protected)
		if !valid {
			return nil
		}
		id := fileIdentityAt(path, name, info)
		if id == "" {
			return ErrStreamSourceGap
		}
		seq := -1
		if protected && ordinal == 0 {
			seq = 0
			if parsed, ok := signalFileChainSequence(filepath.Base(name)); ok {
				seq = parsed
			}
		}
		out = append(out, signalFile{path: name, info: info, id: id, legacyID: fileIdentityLegacyAt(path, info), ordinal: ordinal, chainSeq: seq, protected: protected, compressed: compressed})
		return nil
	}
	if err := add(path, false); err != nil {
		return nil, err
	}
	for _, name := range rotatedSourceCandidates(path) {
		if err := add(name, false); err != nil {
			return nil, err
		}
	}
	if dir := os.Getenv(deviceSignalRecoveryDirEnv); dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if err := add(filepath.Join(dir, entry.Name()), true); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func signalFileOrdinal(source, candidate string, protected bool) (int, bool, bool) {
	if candidate == source {
		return -1, false, true
	}
	base, name := filepath.Base(source), filepath.Base(candidate)
	if protected && base == "ttl.jsonl" {
		if _, ok := signalFileChainSequence(name); ok {
			return 0, true, true
		}
	}
	if protected && strings.HasSuffix(base, ".jsonl") {
		stem := strings.TrimSuffix(base, ".jsonl")
		if (stem == "ttl" || stem == "flow-syn" || stem == "handshake") &&
			strings.HasPrefix(name, stem+"-live-") && strings.HasSuffix(name, ".jsonl") {
			return 0, false, true
		}
	}
	if !strings.HasPrefix(name, base+".") {
		return 0, false, false
	}
	suffix := strings.TrimPrefix(name, base+".")
	compressed := strings.HasSuffix(suffix, ".gz")
	if compressed {
		suffix = strings.TrimSuffix(suffix, ".gz")
	}
	n, err := strconv.Atoi(suffix)
	return n, compressed, err == nil && n > 0 && n <= 1000
}

func signalFileChainSequence(name string) (int, bool) {
	const prefix, suffix = "ttl-chain-", ".jsonl.gz"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return 0, false
	}
	part := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	if len(part) != 12 {
		return 0, false
	}
	for _, digit := range part {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	seq, err := strconv.Atoi(part)
	return seq, err == nil && seq >= 0 && seq <= 100000
}

func validSignalTail(cursor streamlog.SourceCursor) bool {
	return cursor.TailBytes > 0 && cursor.TailBytes <= streamlog.SourceTailProofBytes &&
		cursor.Offset >= int64(cursor.TailBytes) && len(cursor.TailSHA256) == 64
}

func signalRawCursorMatches(file signalFile, cursor streamlog.SourceCursor) bool {
	if cursor.Offset == 0 {
		return true
	}
	if !validSignalTail(cursor) || file.info.Size() < cursor.Offset {
		return false
	}
	f, err := os.Open(file.path)
	if err != nil {
		return false
	}
	defer f.Close()
	tail := make([]byte, cursor.TailBytes)
	if _, err := f.ReadAt(tail, cursor.Offset-int64(cursor.TailBytes)); err != nil {
		return false
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(file.info, after) || after.Size() < cursor.Offset {
		return false
	}
	sum := sha256.Sum256(tail)
	return hex.EncodeToString(sum[:]) == cursor.TailSHA256
}

func uniqueSignalMatch(matches []signalFile) (signalFile, bool) {
	if len(matches) == 0 {
		return signalFile{}, false
	}
	first := matches[0]
	for _, item := range matches[1:] {
		if !os.SameFile(first.info, item.info) {
			return signalFile{}, false
		}
		if item.protected {
			first = item
		}
	}
	return first, true
}

func readSignalRaw(source string, file signalFile, cursor streamlog.SourceCursor, maxBytes int64) (sourceChunk, error) {
	f, err := os.Open(file.path)
	if err != nil {
		return sourceChunk{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(info, file.info) {
		return sourceChunk{}, ErrStreamSourceGap
	}
	// The retained legacy inode is selected only after its committed tail was
	// proved above. readFileChunk uses the currently selected identity mode;
	// preserve the old identity in this one segment until a verified successor.
	read, err := readFileChunk(f, source, info, ingest.Checkpoint{FileID: file.id, Offset: cursor.Offset}, true, maxBytes, false, file.path)
	if err == nil && !read.truncated && file.legacyID == cursor.FileID && file.id != cursor.FileID {
		read.fileID = cursor.FileID
	}
	read.archive = file.path != source
	if err != nil || read.truncated || read.fileID != cursor.FileID {
		return sourceChunk{}, ErrStreamSourceGap
	}
	return read, nil
}

type signalGzipReader struct {
	file           *os.File
	reader         *gzip.Reader
	info           os.FileInfo
	logicalID      string
	length         int64
	offset         int64
	pending        []byte
	tailBytes      int
	tailHash       string
	lastStart      int64
	lastData       []byte
	startTailBytes int
	startTailHash  string
}

func (r *signalGzipReader) close() {
	if r != nil {
		_ = r.reader.Close()
		_ = r.file.Close()
	}
}

// The source lease gives one capture writer per path. This cache only avoids
// re-inflating a gigabyte archive for every one-megabyte durable segment. A
// failed cursor commit makes the cached offset disagree and forces replay.
var signalGzipState = struct {
	sync.Mutex
	bySource map[string]*signalGzipReader
}{bySource: make(map[string]*signalGzipReader)}

func clearSignalGzip(source string) {
	signalGzipState.Lock()
	defer signalGzipState.Unlock()
	if cached := signalGzipState.bySource[source]; cached != nil {
		cached.close()
		delete(signalGzipState.bySource, source)
	}
}

func signalGzipCursorMatches(source string, file signalFile, cursor streamlog.SourceCursor) bool {
	signalGzipState.Lock()
	cache := signalGzipState.bySource[source]
	matched := cache != nil && os.SameFile(cache.info, file.info) && cache.logicalID == cursor.FileID && cacheSupportsCursor(cache, cursor)
	signalGzipState.Unlock()
	if matched {
		return true
	}
	return cursor.Offset == 0 || probeSignalGzipTail(file.path, cursor)
}

func cacheSupportsCursor(cache *signalGzipReader, cursor streamlog.SourceCursor) bool {
	if cache == nil || cache.logicalID != cursor.FileID {
		return false
	}
	if len(cache.lastData) == 0 {
		return cache.offset == cursor.Offset && cache.tailBytes == cursor.TailBytes && cache.tailHash == cursor.TailSHA256
	}
	if cursor.Offset == cache.lastStart {
		return cache.startTailBytes == cursor.TailBytes && cache.startTailHash == cursor.TailSHA256
	}
	if cursor.Offset < cache.lastStart || cursor.Offset > cache.offset {
		return false
	}
	end := cursor.Offset - cache.lastStart
	if cursor.TailBytes <= 0 || int64(cursor.TailBytes) > end {
		return false
	}
	tail := cache.lastData[end-int64(cursor.TailBytes) : end]
	sum := sha256.Sum256(tail)
	return hex.EncodeToString(sum[:]) == cursor.TailSHA256
}

func probeSignalGzipTail(path string, cursor streamlog.SourceCursor) bool {
	if !validSignalTail(cursor) {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return false
	}
	defer zr.Close()
	if _, err := io.CopyN(io.Discard, zr, cursor.Offset-int64(cursor.TailBytes)); err != nil {
		return false
	}
	tail := make([]byte, cursor.TailBytes)
	if _, err := io.ReadFull(zr, tail); err != nil {
		return false
	}
	sum := sha256.Sum256(tail)
	return hex.EncodeToString(sum[:]) == cursor.TailSHA256
}

func readSignalGzip(source string, file signalFile, cursor streamlog.SourceCursor, maxBytes int64) (sourceChunk, error) {
	signalGzipState.Lock()
	defer signalGzipState.Unlock()
	cache := signalGzipState.bySource[source]
	if cache == nil || !os.SameFile(cache.info, file.info) || !cacheSupportsCursor(cache, cursor) {
		if cache != nil {
			cache.close()
			delete(signalGzipState.bySource, source)
		}
		var err error
		cache, err = openVerifiedSignalGzip(file, cursor)
		if err != nil {
			return sourceChunk{}, err
		}
		signalGzipState.bySource[source] = cache
	}
	after, err := cache.file.Stat()
	if err != nil || !os.SameFile(cache.info, after) || cache.info.Size() != after.Size() || !cache.info.ModTime().Equal(after.ModTime()) {
		cache.close()
		delete(signalGzipState.bySource, source)
		return sourceChunk{}, ErrStreamSourceGap
	}
	read := sourceChunk{fileID: cursor.FileID, start: cursor.Offset, end: cursor.Offset, archive: true}
	if len(cache.lastData) > 0 && cursor.Offset < cache.offset {
		read.data = cache.lastData[cursor.Offset-cache.lastStart:]
		read.end = cache.offset
		return read, nil
	}
	if cursor.Offset >= cache.length {
		if cursor.Offset > cache.length {
			return sourceChunk{}, ErrStreamSourceGap
		}
		return read, nil
	}
	buf := make([]byte, maxBytes)
	n := copy(buf, cache.pending)
	cache.pending = nil
	if n < len(buf) {
		more, readErr := io.ReadFull(cache.reader, buf[n:])
		n += more
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return sourceChunk{}, ErrStreamSourceGap
		}
	}
	last := bytes.LastIndexByte(buf[:n], '\n')
	if last < 0 {
		return sourceChunk{}, ErrStreamSourceGap
	}
	read.data = buf[:last+1]
	read.end += int64(len(read.data))
	cache.pending = append(cache.pending, buf[last+1:n]...)
	cache.lastStart, cache.lastData = read.start, read.data
	cache.startTailBytes, cache.startTailHash = cursor.TailBytes, cursor.TailSHA256
	cache.offset = read.end
	tail := read.data
	if len(tail) > streamlog.SourceTailProofBytes {
		tail = tail[len(tail)-streamlog.SourceTailProofBytes:]
	}
	sum := sha256.Sum256(tail)
	cache.tailBytes, cache.tailHash = len(tail), hex.EncodeToString(sum[:])
	return read, nil
}

// Verify the complete gzip member and trailer before using any bytes. The
// cursor tail separately proves which original file this archive represents.
func openVerifiedSignalGzip(file signalFile, cursor streamlog.SourceCursor) (*signalGzipReader, error) {
	f, err := os.Open(file.path)
	if err != nil {
		return nil, ErrStreamSourceGap
	}
	before, err := f.Stat()
	if err != nil || !os.SameFile(before, file.info) {
		f.Close()
		return nil, ErrStreamSourceGap
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, ErrStreamSourceGap
	}
	last := &signalLastByte{}
	length, verifyErr := io.Copy(last, zr)
	closeErr := zr.Close()
	after, statErr := f.Stat()
	if verifyErr != nil || closeErr != nil || statErr != nil || !os.SameFile(before, after) ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || length == 0 || last.value != '\n' || length < cursor.Offset {
		f.Close()
		return nil, ErrStreamSourceGap
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	zr, err = gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, ErrStreamSourceGap
	}
	if _, err := io.CopyN(io.Discard, zr, cursor.Offset); err != nil {
		zr.Close()
		f.Close()
		return nil, ErrStreamSourceGap
	}
	return &signalGzipReader{file: f, reader: zr, info: before, logicalID: cursor.FileID, length: length, offset: cursor.Offset, tailBytes: cursor.TailBytes, tailHash: cursor.TailSHA256}, nil
}

type signalLastByte struct{ value byte }

func (w *signalLastByte) Write(data []byte) (int, error) {
	if len(data) > 0 {
		w.value = data[len(data)-1]
	}
	return len(data), nil
}

// Advance only one numbered rotation at a time. The protected snapshot is
// preferred until its live anchor; after that the active directory must
// still expose the anchor's inode to prove the intervening interval.
func nextSignalFile(path string, files []signalFile, old signalFile) (signalFile, error) {
	if old.protected && old.ordinal == 0 {
		for _, file := range files {
			if file.protected && file.compressed && file.chainSeq == old.chainSeq+1 {
				if old.chainSeq == 0 && !old.compressed {
					// The first compressed link is a duplicate of the live
					// anchor. Without it, successor numbering proves nothing.
					if !signalChainStartsAtLive(files, old) {
						return signalFile{}, ErrStreamSourceGap
					}
				}
				return file, nil
			}
		}
	}
	if old.ordinal == 0 {
		matched := false
		for _, active := range files {
			if !active.protected && active.path != path && os.SameFile(active.info, old.info) {
				old.ordinal = active.ordinal
				old.protected = false
				matched = true
				break
			}
		}
		if !matched {
			// Delay compression changes inode after the protected live
			// hard link was made. Full bytes, length and gzip CRC can still
			// identify the one active archive that replaced it.
			compressed, err := matchingCompressedSignalFile(old, files)
			if err != nil {
				return signalFile{}, err
			}
			old.ordinal = compressed.ordinal
			old.protected = false
		}
	}
	want := old.ordinal - 1
	if want < 0 {
		return signalFile{}, ErrStreamSourceGap
	}
	if old.protected {
		for _, file := range files {
			// The chain's first gzip also has ordinal zero, but it is a
			// duplicate of the protected live anchor, not the successor of
			// a numbered rotation. Cross the raw anchor first.
			if file.protected && file.ordinal == want && (want != 0 || !file.compressed) {
				if want == 0 && !protectedSignalSuccessorProved(files, old, file) {
					return signalFile{}, ErrStreamSourceGap
				}
				return file, nil
			}
		}
		if want > 0 {
			return signalFile{}, ErrStreamSourceGap
		}
		// With no protected live link, the active .1 must still be this
		// exact inode before current can be accepted as its successor.
		seen := false
		for _, file := range files {
			if !file.protected && file.ordinal == 1 && os.SameFile(file.info, old.info) {
				seen = true
			}
		}
		if !seen {
			return signalFile{}, ErrStreamSourceGap
		}
	}
	if want == 0 {
		for _, file := range files {
			if file.path == path {
				return file, nil
			}
		}
		return signalFile{}, ErrStreamSourceGap
	}
	for _, file := range files {
		if !file.protected && file.ordinal == want {
			return file, nil
		}
	}
	return signalFile{}, ErrStreamSourceGap
}

// A recovery directory is operator managed. Even there, an arbitrary live
// hard link cannot establish that no file lies between a protected rotation
// and its successor. Require both anchors to remain visible under adjacent
// active names when crossing into a new file. If either active name has
// already been compressed or rotated again, stop for a new bounded audit.
func protectedSignalSuccessorProved(files []signalFile, old, next signalFile) bool {
	oldOrdinal, nextOrdinal := -1, -1
	for _, active := range files {
		if active.protected {
			continue
		}
		if os.SameFile(active.info, old.info) && active.ordinal > 0 {
			oldOrdinal = active.ordinal
		}
		if os.SameFile(active.info, next.info) {
			if active.ordinal == -1 { // current source follows .1
				nextOrdinal = 0
			} else {
				nextOrdinal = active.ordinal
			}
		}
	}
	if oldOrdinal > 0 && nextOrdinal == oldOrdinal-1 {
		return true
	}
	// Logrotate replaces both original inodes when it compresses a protected
	// .1 and the following protected live anchor. The protected raw bytes may
	// still cross that boundary only when their complete contents match two
	// adjacent active gzip rotations. The first gzip in the durable chain is
	// the independent witness for the live anchor; gzip reads check their CRC.
	if old.ordinal != 1 || next.ordinal != 0 || old.compressed || next.compressed ||
		!old.protected || !next.protected || !signalChainStartsAtLive(files, next) {
		return false
	}
	compressedOld, err := matchingCompressedSignalFile(old, files)
	if err != nil || compressedOld.ordinal < 2 {
		return false
	}
	var first signalFile
	for _, file := range files {
		if file.protected && file.compressed && file.chainSeq == 0 {
			if first.path != "" {
				return false
			}
			first = file
		}
	}
	if first.path == "" {
		return false
	}
	matchedNext := false
	for _, active := range files {
		if active.protected || !active.compressed || !os.SameFile(active.info, first.info) {
			continue
		}
		if matchedNext || active.ordinal < 2 || compressedOld.ordinal != active.ordinal+1 {
			return false
		}
		matchedNext = true
	}
	return matchedNext
}

func signalChainStartsAtLive(files []signalFile, live signalFile) bool {
	var first signalFile
	for _, file := range files {
		if file.protected && file.compressed && file.chainSeq == 0 {
			first = file
			break
		}
	}
	if first.path == "" {
		return false
	}
	liveHash, liveSize, liveOK := hashSignalFile(live, false)
	firstHash, firstSize, firstOK := hashSignalFile(first, true)
	return liveOK && firstOK && liveSize == firstSize && liveHash == firstHash
}

func matchingCompressedSignalFile(old signalFile, files []signalFile) (signalFile, error) {
	originalHash, originalSize, ok := hashSignalFile(old, false)
	if !ok {
		return signalFile{}, ErrStreamSourceGap
	}
	var matched signalFile
	for _, file := range files {
		if file.protected || !file.compressed || file.ordinal < 1 {
			continue
		}
		sum, length, valid := hashSignalFile(file, true)
		if !valid || length != originalSize || sum != originalHash {
			continue
		}
		if matched.path != "" && !os.SameFile(matched.info, file.info) {
			return signalFile{}, ErrStreamSourceGap
		}
		matched = file
	}
	if matched.path == "" {
		return signalFile{}, ErrStreamSourceGap
	}
	return matched, nil
}

func hashSignalFile(file signalFile, compressed bool) ([32]byte, int64, bool) {
	f, err := os.Open(file.path)
	if err != nil {
		return [32]byte{}, 0, false
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !os.SameFile(before, file.info) {
		return [32]byte{}, 0, false
	}
	var reader io.Reader = f
	var zr *gzip.Reader
	if compressed {
		zr, err = gzip.NewReader(f)
		if err != nil {
			return [32]byte{}, 0, false
		}
		defer zr.Close()
		reader = zr
	}
	h := sha256.New()
	length, err := io.Copy(h, reader)
	if err != nil {
		return [32]byte{}, 0, false
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return [32]byte{}, 0, false
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, length, true
}
