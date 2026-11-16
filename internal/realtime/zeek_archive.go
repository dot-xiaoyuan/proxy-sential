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
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/streamlog"
)

var zeekArchiveCache = struct {
	sync.Mutex
	paths map[string]string
}{paths: make(map[string]string)}

const maxCachedZeekArchiveBytes = 64 << 20

var errZeekArchiveTooLarge = errors.New("Zeek archive exceeds bounded decoded cache")

// Two verified decompressed hourly files serve thousands of small source
// segments while capture and archive acknowledgement cross a rotation.
// The 128 MiB ceiling is fixed; a restart or an oversized archive falls back
// to the original gzip proof path.
type decodedZeekEntry struct {
	path string
	info os.FileInfo
	data []byte
}

var zeekDecodedArchive = struct {
	sync.Mutex
	entries [2]decodedZeekEntry
	next    int
}{}

func cachedDecodedZeekArchive(path string) ([]byte, os.FileInfo, error) {
	zeekDecodedArchive.Lock()
	defer zeekDecodedArchive.Unlock()
	current, err := os.Stat(path)
	if err != nil || !current.Mode().IsRegular() {
		return nil, nil, ErrStreamArchivePending
	}
	for index := range zeekDecodedArchive.entries {
		entry := &zeekDecodedArchive.entries[index]
		if entry.path != path {
			continue
		}
		if entry.info != nil && os.SameFile(entry.info, current) && entry.info.Size() == current.Size() &&
			entry.info.ModTime().Equal(current.ModTime()) {
			return entry.data, current, nil
		}
		*entry = decodedZeekEntry{}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, ErrStreamArchivePending
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(before, current) {
		return nil, nil, ErrStreamArchivePending
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, ErrStreamArchivePending
	}
	data, readErr := io.ReadAll(io.LimitReader(zr, maxCachedZeekArchiveBytes+1))
	closeErr := zr.Close()
	if len(data) > maxCachedZeekArchiveBytes {
		return nil, nil, errZeekArchiveTooLarge
	}
	if readErr != nil || closeErr != nil {
		return nil, nil, ErrStreamArchivePending
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, nil, ErrStreamArchivePending
	}
	zeekDecodedArchive.entries[zeekDecodedArchive.next] = decodedZeekEntry{path: path, info: after, data: data}
	zeekDecodedArchive.next = (zeekDecodedArchive.next + 1) % len(zeekDecodedArchive.entries)
	return data, after, nil
}

func cachedZeekArchive(key string) string {
	zeekArchiveCache.Lock()
	defer zeekArchiveCache.Unlock()
	return zeekArchiveCache.paths[key]
}

func rememberZeekArchive(key, path string) {
	zeekArchiveCache.Lock()
	defer zeekArchiveCache.Unlock()
	if len(zeekArchiveCache.paths) >= 128 {
		clear(zeekArchiveCache.paths)
	}
	zeekArchiveCache.paths[key] = path
}

func forgetZeekArchive(key string) {
	zeekArchiveCache.Lock()
	defer zeekArchiveCache.Unlock()
	delete(zeekArchiveCache.paths, key)
}

// Zeek moves hourly files out of current/ and compresses them. The compressed
// inode is not the source inode, so prove continuity with the last committed
// source bytes before reading its unprocessed tail or the replacement file.
func currentZeekTailProof(path string, cursor streamlog.SourceCursor) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fileIdentity(path, before) != cursor.FileID || before.Size() < cursor.Offset {
		return nil, ErrStreamSourceGap
	}
	n := int(cursor.Offset)
	if n > streamlog.SourceTailProofBytes {
		n = streamlog.SourceTailProofBytes
	}
	if n == 0 {
		return nil, ErrStreamSourceGap
	}
	tail := make([]byte, n)
	if _, err := f.ReadAt(tail, cursor.Offset-int64(n)); err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() < cursor.Offset {
		return nil, ErrStreamSourceGap
	}
	return tail, nil
}

func readZeekBindingChunk(path string, cursor streamlog.SourceCursor, maxBytes int64) (sourceChunk, error) {
	info, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return sourceChunk{}, err
	}
	if err == nil && fileIdentity(path, info) == cursor.FileID {
		// Zeek can recycle an inode after an hourly compressed rotation. The
		// committed tail, rather than path+inode alone, proves this is still
		// the same byte stream.
		if cursor.Offset == 0 {
			return readSourceChunk(path, ingest.Checkpoint{FileID: cursor.FileID, Offset: cursor.Offset}, true, maxBytes, true)
		}
		if cursor.TailBytes <= 0 || cursor.TailBytes > streamlog.SourceTailProofBytes || len(cursor.TailSHA256) != 64 {
			return sourceChunk{}, ErrStreamSourceGap
		}
		if tail, proofErr := currentZeekTailProof(path, cursor); proofErr == nil && len(tail) >= cursor.TailBytes {
			sum := sha256.Sum256(tail[len(tail)-cursor.TailBytes:])
			if hex.EncodeToString(sum[:]) == cursor.TailSHA256 {
				return readSourceChunk(path, ingest.Checkpoint{FileID: cursor.FileID, Offset: cursor.Offset}, true, maxBytes, true)
			}
		}
	}
	if cursor.TailBytes <= 0 || cursor.TailBytes > streamlog.SourceTailProofBytes || cursor.Offset < int64(cursor.TailBytes) || len(cursor.TailSHA256) != 64 {
		return sourceChunk{}, ErrStreamSourceGap
	}
	base := strings.TrimSuffix(filepath.Base(path), ".log")
	pattern := filepath.Join(filepath.Dir(filepath.Dir(path)), "????-??-??", base+".*.log.gz")
	archives, err := filepath.Glob(pattern)
	if err != nil {
		return sourceChunk{}, err
	}
	matched, err := zeekArchiveIndexForCursor(path, cursor, archives)
	if err != nil {
		return sourceChunk{}, err
	}
	if matched < 0 {
		return sourceChunk{}, ErrStreamArchivePending
	}
	data, atEOF, err := readZeekArchiveChunkAt(archives[matched], cursor.Offset, maxBytes)
	if err != nil {
		return sourceChunk{}, err
	}
	if len(data) > 0 {
		return sourceChunk{data: data, fileID: cursor.FileID, start: cursor.Offset, end: cursor.Offset + int64(len(data)), archive: true}, nil
	}
	// Only a verified gzip EOF proves that the old archive has been drained.
	// An incomplete compressed file must never trigger a rotation.
	if !atEOF {
		return sourceChunk{}, ErrStreamArchivePending
	}
	if matched+1 < len(archives) {
		next := archives[matched+1]
		if !consecutiveZeekArchives(archives[matched], next) {
			return sourceChunk{}, ErrStreamSourceGap
		}
		return readFirstZeekArchiveChunk(path, next, maxBytes)
	}
	if info == nil {
		return sourceChunk{}, ErrStreamArchivePending
	}
	read, err := readSourceChunk(path, ingest.Checkpoint{}, false, maxBytes, true)
	if err != nil {
		return sourceChunk{}, err
	}
	read.verifiedRotation = true
	return read, nil
}

func readZeekArchiveChunkAt(path string, offset, maxBytes int64) ([]byte, bool, error) {
	if maxBytes <= 0 || maxBytes > streamReadLimit || offset < 0 {
		return nil, false, fmt.Errorf("invalid Zeek archive read bound")
	}
	if decoded, _, err := cachedDecodedZeekArchive(path); err == nil {
		if offset > int64(len(decoded)) {
			return nil, false, ErrStreamArchivePending
		}
		if offset == int64(len(decoded)) {
			return nil, true, nil
		}
		end := min(int64(len(decoded)), offset+maxBytes)
		window := decoded[offset:end]
		last := bytes.LastIndexByte(window, '\n')
		if last < 0 {
			return nil, false, streamlog.ErrSegmentTooLarge
		}
		return append([]byte(nil), window[:last+1]...), false, nil
	} else if !errors.Is(err, errZeekArchiveTooLarge) {
		return nil, false, err
	}
	// Large archives retain the old bounded streaming path; no unverified
	// bytes are supplied to a source segment when caching is unavailable.
	archive, err := os.Open(path)
	if err != nil {
		return nil, false, ErrStreamArchivePending
	}
	defer archive.Close()
	zr, err := gzip.NewReader(archive)
	if err != nil {
		return nil, false, ErrStreamArchivePending
	}
	defer zr.Close()
	if _, err := io.CopyN(io.Discard, zr, offset); err != nil {
		return nil, false, ErrStreamArchivePending
	}
	buf := make([]byte, maxBytes)
	n, err := io.ReadFull(zr, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false, ErrStreamArchivePending
	}
	if n == 0 {
		return nil, err == io.EOF, nil
	}
	last := bytes.LastIndexByte(buf[:n], '\n')
	if last < 0 {
		return nil, false, streamlog.ErrSegmentTooLarge
	}
	return buf[:last+1], false, nil
}

// A fixed last-N tail silently loses an older but still retained cursor.
// Cache verified physical archives while draining them; otherwise search the
// entire retained chain and require a unique tail match. Legacy cursors may
// need one full scan after process restart; all later chunks reuse the proven
// archive. Unknown cursor IDs are never guessed from a possibly reused inode.
func zeekArchiveIndexForCursor(path string, cursor streamlog.SourceCursor, archives []string) (int, error) {
	cacheKey := path + "\x00" + cursor.FileID
	tryPath := func(candidate string) int {
		if candidate == "" {
			return -1
		}
		index := sort.SearchStrings(archives, candidate)
		if index >= len(archives) || archives[index] != candidate {
			return -1
		}
		if _, _, ok := zeekArchiveInterval(candidate); !ok {
			return -1
		}
		valid, err := zeekArchiveMatchesCursor(candidate, cursor)
		if err != nil || !valid {
			return -1
		}
		rememberZeekArchive(cacheKey, candidate)
		return index
	}
	if index := tryPath(cachedZeekArchive(cacheKey)); index >= 0 {
		return index, nil
	}
	forgetZeekArchive(cacheKey)
	matched := -1
	for index, candidate := range archives {
		valid, err := zeekArchiveMatchesCursor(candidate, cursor)
		if err != nil || !valid {
			continue
		}
		if matched >= 0 {
			return -1, streamlog.ErrContentConflict
		}
		matched = index
	}
	if matched >= 0 {
		rememberZeekArchive(cacheKey, archives[matched])
	}
	return matched, nil
}

// A cursor can lag across several completed Zeek rotations. It must enter
// each intervening archive in filename order, with a new generation for each
// file, before it may follow current/. An absent interval remains a hard gap.
func consecutiveZeekArchives(previous, next string) bool {
	_, end, ok := zeekArchiveInterval(previous)
	if !ok {
		return false
	}
	start, _, ok := zeekArchiveInterval(next)
	return ok && end.Equal(start)
}

func zeekArchiveInterval(path string) (time.Time, time.Time, bool) {
	name := filepath.Base(path)
	if !strings.HasSuffix(name, ".log.gz") {
		return time.Time{}, time.Time{}, false
	}
	name = strings.TrimSuffix(name, ".log.gz")
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return time.Time{}, time.Time{}, false
	}
	period := name[dot+1:]
	parts := strings.Split(period, "-")
	if len(parts) != 2 {
		return time.Time{}, time.Time{}, false
	}
	date := filepath.Base(filepath.Dir(path))
	start, err := time.Parse("2006-01-02 15:04:05", date+" "+parts[0])
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	end, err := time.Parse("2006-01-02 15:04:05", date+" "+parts[1])
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	if !end.After(start) {
		end = end.Add(24 * time.Hour)
	}
	return start, end, true
}

func readFirstZeekArchiveChunk(sourcePath, archivePath string, maxBytes int64) (sourceChunk, error) {
	if maxBytes <= 0 || maxBytes > streamReadLimit {
		return sourceChunk{}, fmt.Errorf("invalid Zeek archive read bound")
	}
	if decoded, info, err := cachedDecodedZeekArchive(archivePath); err == nil {
		if len(decoded) == 0 {
			return sourceChunk{}, ErrStreamSourceGap
		}
		end := min(int64(len(decoded)), maxBytes)
		last := bytes.LastIndexByte(decoded[:end], '\n')
		if last < 0 {
			return sourceChunk{}, streamlog.ErrSegmentTooLarge
		}
		fileID := fileIdentityAt(sourcePath, archivePath, info)
		rememberZeekArchive(sourcePath+"\x00"+fileID, archivePath)
		data := append([]byte(nil), decoded[:last+1]...)
		return sourceChunk{data: data, fileID: fileID, start: 0, end: int64(len(data)), archive: true, verifiedRotation: true}, nil
	} else if !errors.Is(err, errZeekArchiveTooLarge) {
		return sourceChunk{}, err
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return sourceChunk{}, ErrStreamArchivePending
	}
	defer archive.Close()
	before, err := archive.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return sourceChunk{}, ErrStreamArchivePending
	}
	// The successor is a new source generation. Check its gzip trailer and
	// CRC before committing a descriptor that depends on its original bytes.
	verify, err := gzip.NewReader(archive)
	if err != nil {
		return sourceChunk{}, ErrStreamArchivePending
	}
	_, verifyErr := io.Copy(io.Discard, verify)
	closeErr := verify.Close()
	if verifyErr != nil || closeErr != nil {
		return sourceChunk{}, ErrStreamArchivePending
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return sourceChunk{}, ErrStreamArchivePending
	}
	zr, err := gzip.NewReader(archive)
	if err != nil {
		return sourceChunk{}, ErrStreamArchivePending
	}
	defer zr.Close()
	if maxBytes <= 0 || maxBytes > streamReadLimit {
		return sourceChunk{}, fmt.Errorf("invalid Zeek archive read bound")
	}
	buf := make([]byte, maxBytes)
	n, err := io.ReadFull(zr, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return sourceChunk{}, ErrStreamArchivePending
	}
	if n == 0 {
		return sourceChunk{}, ErrStreamSourceGap
	}
	last := bytes.LastIndexByte(buf[:n], '\n')
	if last < 0 {
		return sourceChunk{}, streamlog.ErrSegmentTooLarge
	}
	after, err := archive.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return sourceChunk{}, ErrStreamArchivePending
	}
	data := buf[:last+1]
	fileID := fileIdentityAt(sourcePath, archivePath, before)
	rememberZeekArchive(sourcePath+"\x00"+fileID, archivePath)
	return sourceChunk{data: data, fileID: fileID, start: 0, end: int64(len(data)), archive: true, verifiedRotation: true}, nil
}

func zeekArchiveMatchesCursor(path string, cursor streamlog.SourceCursor) (bool, error) {
	if decoded, _, err := cachedDecodedZeekArchive(path); err == nil {
		if cursor.Offset < int64(cursor.TailBytes) || cursor.Offset > int64(len(decoded)) {
			return false, nil
		}
		sum := sha256.Sum256(decoded[cursor.Offset-int64(cursor.TailBytes) : cursor.Offset])
		return hex.EncodeToString(sum[:]) == cursor.TailSHA256, nil
	} else if !errors.Is(err, errZeekArchiveTooLarge) {
		return false, err
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return false, err
	}
	defer zr.Close()
	before := cursor.Offset - int64(cursor.TailBytes)
	if _, err := io.CopyN(io.Discard, zr, before); err != nil {
		return false, err
	}
	tail := make([]byte, cursor.TailBytes)
	if _, err := io.ReadFull(zr, tail); err != nil {
		return false, err
	}
	sum := sha256.Sum256(tail)
	return hex.EncodeToString(sum[:]) == cursor.TailSHA256, nil
}

// resolveZeekSourceRaw rehydrates one immutable descriptor. The exact source
// bytes are accepted only after file identity (for current/) or a unique
// cryptographic match (for a compressed rotation) has been established.
// ResolveZeekSourceRaw also supplies the same proof to the stopped-source
// operator repair command.
func ResolveZeekSourceRaw(segment streamlog.Segment) ([]byte, error) {
	return resolveZeekSourceRaw(segment)
}

func resolveZeekSourceRaw(segment streamlog.Segment) ([]byte, error) {
	if segment.Source != "zeek-dhcp-binding" || !segment.SourceBackedRaw ||
		segment.StartOffset < 0 || segment.EndOffset <= segment.StartOffset ||
		segment.EndOffset-segment.StartOffset > streamReadLimit || len(segment.RawSHA256) != 64 {
		return nil, streamlog.ErrContentConflict
	}
	length := segment.EndOffset - segment.StartOffset
	if f, err := os.Open(segment.SourcePath); err == nil {
		info, statErr := f.Stat()
		// Zeek may reuse the inode for a shorter replacement file. Its size
		// cannot disprove the old descriptor; search the hashed rotation below.
		if statErr == nil && fileIdentity(segment.SourcePath, info) == segment.FileID && info.Size() >= segment.EndOffset {
			buf := make([]byte, length)
			_, readErr := f.ReadAt(buf, segment.StartOffset)
			_ = f.Close()
			if readErr != nil {
				return nil, readErr
			}
			sum := sha256.Sum256(buf)
			if hex.EncodeToString(sum[:]) == segment.RawSHA256 {
				return buf, nil
			}
			// The inode may have been recycled. A unique matching compressed
			// archive below can still recover this immutable source slice.
		}
		_ = f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	cacheKey := segment.SourcePath + "\x00" + segment.FileID
	if path := cachedZeekArchive(cacheKey); path != "" {
		if raw := matchingZeekArchiveSlice(path, segment, length); raw != nil {
			return raw, nil
		}
		forgetZeekArchive(cacheKey)
	}
	base := strings.TrimSuffix(filepath.Base(segment.SourcePath), ".log")
	pattern := filepath.Join(filepath.Dir(filepath.Dir(segment.SourcePath)), "????-??-??", base+".*.log.gz")
	archives, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var matched []byte
	var matchedPath string
	for _, path := range archives {
		candidate := matchingZeekArchiveSlice(path, segment, length)
		if candidate == nil {
			continue
		}
		if matched != nil {
			return nil, streamlog.ErrContentConflict
		}
		matched, matchedPath = candidate, path
	}
	if matched == nil {
		return nil, ErrStreamArchivePending
	}
	rememberZeekArchive(cacheKey, matchedPath)
	return matched, nil
}

func matchingZeekArchiveSlice(path string, segment streamlog.Segment, length int64) []byte {
	if decoded, _, err := cachedDecodedZeekArchive(path); err == nil {
		if segment.StartOffset < 0 || segment.EndOffset > int64(len(decoded)) ||
			segment.EndOffset-segment.StartOffset != length {
			return nil
		}
		candidate := decoded[segment.StartOffset:segment.EndOffset]
		sum := sha256.Sum256(candidate)
		if hex.EncodeToString(sum[:]) != segment.RawSHA256 {
			return nil
		}
		return append([]byte(nil), candidate...)
	} else if !errors.Is(err, errZeekArchiveTooLarge) {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	defer zr.Close()
	if _, err := io.CopyN(io.Discard, zr, segment.StartOffset); err != nil {
		return nil
	}
	candidate := make([]byte, length)
	if _, err := io.ReadFull(zr, candidate); err != nil {
		return nil
	}
	sum := sha256.Sum256(candidate)
	if hex.EncodeToString(sum[:]) != segment.RawSHA256 {
		return nil
	}
	return candidate
}
