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
	"strings"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/streamlog"
)

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
	if len(archives) > 72 {
		archives = archives[len(archives)-72:]
	}
	matched := -1
	for i, archive := range archives {
		valid, err := zeekArchiveMatchesCursor(archive, cursor)
		if err != nil {
			continue
		} // A still-compressing archive is retried below.
		if valid {
			if matched >= 0 {
				return sourceChunk{}, streamlog.ErrContentConflict
			}
			matched = i
		}
	}
	if matched < 0 {
		return sourceChunk{}, ErrStreamArchivePending
	}
	// A stopped reader may have missed another whole hourly archive. Do not
	// jump straight to current/ and silently omit it.
	if matched != len(archives)-1 {
		return sourceChunk{}, ErrStreamSourceGap
	}
	archive, err := os.Open(archives[matched])
	if err != nil {
		return sourceChunk{}, ErrStreamArchivePending
	}
	defer archive.Close()
	zr, err := gzip.NewReader(archive)
	if err != nil {
		return sourceChunk{}, ErrStreamArchivePending
	}
	defer zr.Close()
	if _, err := io.CopyN(io.Discard, zr, cursor.Offset); err != nil {
		return sourceChunk{}, ErrStreamArchivePending
	}
	if maxBytes <= 0 || maxBytes > 1<<20 {
		return sourceChunk{}, fmt.Errorf("invalid Zeek archive read bound")
	}
	buf := make([]byte, maxBytes)
	n, err := io.ReadFull(zr, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return sourceChunk{}, ErrStreamArchivePending
	}
	if n > 0 {
		last := bytes.LastIndexByte(buf[:n], '\n')
		if last < 0 {
			return sourceChunk{}, streamlog.ErrSegmentTooLarge
		}
		data := buf[:last+1]
		return sourceChunk{data: data, fileID: cursor.FileID, start: cursor.Offset, end: cursor.Offset + int64(len(data)), archive: true}, nil
	}
	if err == nil {
		return sourceChunk{}, ErrStreamArchivePending
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

func zeekArchiveMatchesCursor(path string, cursor streamlog.SourceCursor) (bool, error) {
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
		if statErr == nil && fileIdentity(segment.SourcePath, info) == segment.FileID && info.Size() < segment.EndOffset {
			_ = f.Close()
			return nil, ErrStreamSourceGap
		}
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
	base := strings.TrimSuffix(filepath.Base(segment.SourcePath), ".log")
	pattern := filepath.Join(filepath.Dir(filepath.Dir(segment.SourcePath)), "????-??-??", base+".*.log.gz")
	archives, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var matched []byte
	for _, path := range archives {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			continue
		}
		_, err = io.CopyN(io.Discard, zr, segment.StartOffset)
		if err == nil {
			candidate := make([]byte, length)
			_, err = io.ReadFull(zr, candidate)
			if err == nil {
				sum := sha256.Sum256(candidate)
				if hex.EncodeToString(sum[:]) == segment.RawSHA256 {
					if matched != nil {
						_ = zr.Close()
						_ = f.Close()
						return nil, streamlog.ErrContentConflict
					}
					matched = candidate
				}
			}
		}
		_ = zr.Close()
		_ = f.Close()
	}
	if matched == nil {
		return nil, ErrStreamArchivePending
	}
	return matched, nil
}
