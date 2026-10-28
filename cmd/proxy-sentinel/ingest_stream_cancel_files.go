package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/streamlog"
)

// Only compact ranges and hashes enter the ledger. No old record is parsed as
// an event, re-enqueued, or copied. The original files and journal stay in place.
type cancelledSourceFiles struct {
	FileID         string             `json:"file_id"`
	Offset         int64              `json:"offset"`
	TailBytes      int                `json:"tail_bytes"`
	TailSHA256     string             `json:"tail_sha256"`
	Files          []string           `json:"retained_files"`
	RetainedFiles  []string           `json:"protected_files,omitempty"`
	FileIdentities []string           `json:"file_identities"`
	FileSizes      []int64            `json:"file_sizes"`
	Entries        []zeekDiscardEntry `json:"ranges"`
}

func cancellationSourcePaths(cursor streamlog.SourceCursor) ([]string, error) {
	if cursor.Source == "zeek-dhcp-binding" {
		base := strings.TrimSuffix(filepath.Base(cursor.Path), ".log")
		paths, e := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(cursor.Path)), "????-??-??", base+".*.log.gz"))
		if e != nil {
			return nil, e
		}
		if len(paths) > 168 {
			return nil, errors.New("cancellation exceeds 168 retained hourly files")
		}
		sort.Strings(paths)
		return append(paths, cursor.Path), nil
	}
	if cursor.Source != "device-signals" {
		return nil, errors.New("unsupported file cancellation source")
	}
	entries, e := os.ReadDir(filepath.Dir(cursor.Path))
	if e != nil {
		return nil, e
	}
	base := filepath.Base(cursor.Path)
	numeric := regexp.MustCompile(`^\.(\d+)(\.gz)?$`)
	dated := regexp.MustCompile(`^-\d{8}-\d{6}(\.gz)?$`)
	type item struct {
		path string
		n    int
		key  string
	}
	items := []item{}
	seen := map[string]bool{}
	mode := ""
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), base) || entry.Name() == base {
			continue
		}
		suffix := strings.TrimPrefix(entry.Name(), base)
		v := item{path: filepath.Join(filepath.Dir(cursor.Path), entry.Name())}
		nextMode := ""
		if match := numeric.FindStringSubmatch(suffix); match != nil {
			v.n, e = strconv.Atoi(match[1])
			if e != nil || v.n < 1 {
				return nil, errors.New("invalid source rotation number")
			}
			v.key = match[1]
			nextMode = "numeric"
		} else if dated.MatchString(suffix) {
			v.key = strings.TrimSuffix(suffix, ".gz")
			nextMode = "date"
		} else {
			continue
		}
		if seen[v.key] || mode != "" && mode != nextMode {
			return nil, errors.New("ambiguous source rotation inventory")
		}
		mode = nextMode
		seen[v.key] = true
		items = append(items, v)
	}
	if len(items) > 64 {
		return nil, errors.New("cancellation exceeds 64 retained device files")
	}
	sort.Slice(items, func(i, j int) bool {
		if mode == "numeric" {
			return items[i].n > items[j].n
		}
		return items[i].key < items[j].key
	})
	if mode == "numeric" {
		for i, item := range items {
			if item.n != len(items)-i {
				return nil, errors.New("source rotation inventory contains a missing generation")
			}
		}
	}
	paths := make([]string, 0, len(items)+1)
	for _, item := range items {
		paths = append(paths, item.path)
	}
	return append(paths, cursor.Path), nil
}

type cancellationReadBudget struct{ remaining int64 }

func (b *cancellationReadBudget) take(n int64) error {
	if n < 0 || n > b.remaining {
		return errors.New("source cancellation exceeds decoded byte bound")
	}
	b.remaining -= n
	return nil
}

func openCancellationFile(path string) (*os.File, io.Reader, func() error, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, nil, e
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, nil, errors.New("source audit requires regular retained files")
	}
	if strings.HasSuffix(path, ".gz") {
		z, e := gzip.NewReader(f)
		if e != nil {
			f.Close()
			return nil, nil, nil, e
		}
		return f, z, z.Close, nil
	}
	return f, io.LimitReader(f, info.Size()), func() error { return nil }, nil
}

func matchesCancellationCursor(cursor streamlog.SourceCursor, path string, budget *cancellationReadBudget) (bool, error) {
	f, r, closeReader, e := openCancellationFile(path)
	if e != nil {
		return false, e
	}
	defer f.Close()
	defer closeReader()
	info, e := f.Stat()
	if e != nil {
		return false, e
	}
	if !strings.HasSuffix(path, ".gz") {
		if realtime.FileIdentity(cursor.Path, info) != cursor.FileID {
			return false, nil
		}
		if cursor.Offset > info.Size() {
			return false, nil
		}
		if _, e = f.Seek(cursor.Offset-int64(cursor.TailBytes), io.SeekStart); e != nil {
			return false, e
		}
		r = f
	} else {
		if e = budget.take(cursor.Offset); e != nil {
			return false, e
		}
		if _, e = io.CopyN(io.Discard, r, cursor.Offset-int64(cursor.TailBytes)); e != nil {
			if errors.Is(e, io.EOF) {
				return false, nil
			}
			return false, e
		}
	}
	tail := make([]byte, cursor.TailBytes)
	if _, e = io.ReadFull(r, tail); e != nil {
		if errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, e
	}
	sum := sha256.Sum256(tail)
	return hex.EncodeToString(sum[:]) == cursor.TailSHA256, nil
}

func snapshotCancelledSourceFiles(cursor streamlog.SourceCursor, maxDecoded int64) (*cancelledSourceFiles, error) {
	if cursor.TailBytes <= 0 || cursor.TailBytes > streamlog.SourceTailProofBytes || cursor.Offset < int64(cursor.TailBytes) || len(cursor.TailSHA256) != 64 {
		return nil, errors.New("source cancellation needs a verified original cursor tail")
	}
	paths, e := cancellationSourcePaths(cursor)
	if e != nil {
		return nil, e
	}
	budget := &cancellationReadBudget{remaining: maxDecoded}
	match := -1
	// An uncompressed original keeps its inode; avoid decompressing older files
	// when that original is still retained (notably the multi-GB handshake log).
	for i, path := range paths {
		if strings.HasSuffix(path, ".gz") {
			continue
		}
		ok, e := matchesCancellationCursor(cursor, path, budget)
		if e != nil {
			return nil, e
		}
		if ok {
			if match >= 0 {
				return nil, streamlog.ErrContentConflict
			}
			match = i
		}
	}
	if match < 0 {
		for i, path := range paths {
			if !strings.HasSuffix(path, ".gz") {
				continue
			}
			ok, e := matchesCancellationCursor(cursor, path, budget)
			if e != nil {
				return nil, e
			}
			if ok {
				if match >= 0 {
					return nil, streamlog.ErrContentConflict
				}
				match = i
			}
		}
	}
	if match < 0 {
		return nil, errors.New("original cursor has no unique retained source anchor; cancellation refused")
	}
	result := &cancelledSourceFiles{Files: append([]string(nil), paths[match:]...)}
	for i := match; i < len(paths); i++ {
		path := paths[i]
		f, r, closeReader, e := openCancellationFile(path)
		if e != nil {
			return nil, e
		}
		before, e := f.Stat()
		if e != nil {
			closeReader()
			f.Close()
			return nil, e
		}
		from := int64(0)
		if i == match {
			from = cursor.Offset
		}
		if strings.HasSuffix(path, ".gz") {
			if e = budget.take(from); e == nil {
				_, e = io.CopyN(io.Discard, r, from)
			}
		} else {
			_, e = f.Seek(from, io.SeekStart)
			r = io.LimitReader(f, before.Size()-from)
		}
		if e != nil {
			closeReader()
			f.Close()
			return nil, e
		}
		fileID := realtime.FileIdentity(cursor.Path, before)
		result.FileIdentities = append(result.FileIdentities, realtime.FileIdentity(path, before))
		result.FileSizes = append(result.FileSizes, before.Size())
		if strings.HasSuffix(path, ".gz") {
			fileID = "retained-gzip:" + path
		}
		entries, offset, e := scanCancelledSourceRanges(r, from, fileID, cursor.Source == "zeek-dhcp-binding", i == len(paths)-1, budget)
		closeErr := closeReader()
		after, statErr := os.Stat(path)
		f.Close()
		if e != nil {
			return nil, e
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if statErr != nil || !os.SameFile(before, after) || after.Size() < before.Size() || i < len(paths)-1 && after.Size() != before.Size() {
			return nil, errors.New("retained source changed during cancellation audit")
		}
		result.Entries = append(result.Entries, entries...)
		if len(result.Entries) > 4096 {
			return nil, errors.New("cancellation exceeds 4096 compact ranges")
		}
		if i == len(paths)-1 {
			result.FileID, result.Offset = fileID, offset
			if offset > 0 {
				result.TailBytes = int(min(offset, int64(streamlog.SourceTailProofBytes)))
				tail := make([]byte, result.TailBytes)
				current, e := os.Open(path)
				if e != nil {
					return nil, e
				}
				_, e = current.ReadAt(tail, offset-int64(result.TailBytes))
				current.Close()
				if e != nil {
					return nil, e
				}
				sum := sha256.Sum256(tail)
				result.TailSHA256 = hex.EncodeToString(sum[:])
			}
		}
	}
	if e = validateCancellationBoundary(cursor, result); e != nil {
		return nil, e
	}
	// Inventory must also be stable: a new rotation must not fall between the
	// audited closed generations and the current prefix.
	after, e := cancellationSourcePaths(cursor)
	if e != nil {
		return nil, e
	}
	if strings.Join(paths, "\x00") != strings.Join(after, "\x00") {
		return nil, errors.New("source rotated during cancellation audit")
	}
	return result, nil
}

// Hardlinks retain the original inode without creating another raw copy.
// The audit directory must share a filesystem with the source; otherwise the
// command refuses cancellation and leaves the source and journal unchanged.
func retainCancellationFiles(audit *cancelledSourceFiles, dir string) error {
	if len(audit.Files) == 0 || len(audit.FileIdentities) != len(audit.Files) {
		return streamlog.ErrContentConflict
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return streamlog.ErrContentConflict
	}
	for i, path := range audit.Files {
		before, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !before.Mode().IsRegular() || realtime.FileIdentity(path, before) != audit.FileIdentities[i] {
			return streamlog.ErrContentConflict
		}
		sum := sha256.Sum256([]byte(audit.FileIdentities[i]))
		name := filepath.Join(dir, hex.EncodeToString(sum[:])+filepath.Ext(path))
		if err = os.Link(path, name); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		protected, err := os.Lstat(name)
		if err != nil || !protected.Mode().IsRegular() || !os.SameFile(before, protected) {
			return streamlog.ErrContentConflict
		}
		audit.RetainedFiles = append(audit.RetainedFiles, name)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Verify the fixed ranges from protected originals on preview/apply retries.
// Appends to the current file are permitted, but cannot move the boundary.
func validateRetainedCancellationFiles(cursor streamlog.SourceCursor, audit *cancelledSourceFiles) error {
	n := len(audit.Files)
	if n == 0 || n != len(audit.RetainedFiles) || n != len(audit.FileIdentities) || n != len(audit.FileSizes) {
		return streamlog.ErrContentConflict
	}
	budget := &cancellationReadBudget{remaining: 16 << 30}
	entry := 0
	for i, path := range audit.Files {
		protected := audit.RetainedFiles[i]
		info, err := os.Lstat(protected)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || realtime.FileIdentity(path, info) != audit.FileIdentities[i] || info.Size() < audit.FileSizes[i] || i < n-1 && info.Size() != audit.FileSizes[i] {
			return streamlog.ErrContentConflict
		}
		f, r, closeReader, err := openCancellationFile(protected)
		if err != nil {
			return err
		}
		err = func() error {
			defer f.Close()
			defer closeReader()
			opened, err := f.Stat()
			if err != nil || !os.SameFile(info, opened) {
				return streamlog.ErrContentConflict
			}
			from := int64(0)
			if i == 0 {
				from = cursor.Offset
			}
			fileID := realtime.FileIdentity(cursor.Path, info)
			if strings.HasSuffix(path, ".gz") {
				fileID = "retained-gzip:" + path
				if err = budget.take(from); err != nil {
					return err
				}
				if _, err = io.CopyN(io.Discard, r, from); err != nil {
					return err
				}
			} else {
				if _, err = f.Seek(from, io.SeekStart); err != nil {
					return err
				}
				r = f
			}
			for entry < len(audit.Entries) && strings.HasPrefix(audit.Entries[entry].LegacyReference, fileID+":") {
				v := audit.Entries[entry]
				if v.UnprocessedBytes <= 0 || v.LegacyReference != fmt.Sprintf("%s:%d:%d", fileID, from, from+v.UnprocessedBytes) {
					return streamlog.ErrContentConflict
				}
				if err = budget.take(v.UnprocessedBytes); err != nil {
					return err
				}
				hash := sha256.New()
				if _, err = io.CopyN(hash, r, v.UnprocessedBytes); err != nil {
					return err
				}
				if hex.EncodeToString(hash.Sum(nil)) != v.ContentSHA256 {
					return streamlog.ErrContentConflict
				}
				from += v.UnprocessedBytes
				entry++
			}
			if i == n-1 && from != audit.Offset {
				return streamlog.ErrContentConflict
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	if entry != len(audit.Entries) {
		return streamlog.ErrContentConflict
	}
	return nil
}

func scanCancelledSourceRanges(r io.Reader, from int64, fileID string, zeek, current bool, budget *cancellationReadBudget) ([]zeekDiscardEntry, int64, error) {
	reader := bufio.NewReaderSize(r, 1<<20)
	hash := sha256.New()
	start, offset, records := from, from, int64(0)
	entries := []zeekDiscardEntry{}
	finish := func() {
		if offset == start {
			return
		}
		entries = append(entries, zeekDiscardEntry{LegacyKind: "stream_retirement_unread_chunk", LegacyReference: fmt.Sprintf("%s:%d:%d", fileID, start, offset), LegacyStatus: "cancelled_unprocessed", ContentSHA256: hex.EncodeToString(hash.Sum(nil)), UnprocessedRecords: records, UnprocessedBytes: offset - start})
		start = offset
		records = 0
		hash.Reset()
	}
	for {
		line, e := reader.ReadSlice('\n')
		if b := budget.take(int64(len(line))); b != nil {
			return nil, 0, b
		}
		if errors.Is(e, io.EOF) {
			if len(line) > 0 && !current {
				return nil, 0, errors.New("closed source has an incomplete final record")
			}
			break
		}
		if e != nil {
			return nil, 0, fmt.Errorf("bounded source cancellation read: %w", e)
		}
		hash.Write(line)
		offset += int64(len(line))
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 && (!zeek || trimmed[0] != '#') {
			records++
		}
		if offset-start >= 8<<20 {
			finish()
		}
		if len(entries) > 4096 {
			return nil, 0, errors.New("source cancellation exceeds compact range bound")
		}
	}
	finish()
	return entries, offset, nil
}

func validateCancellationBoundary(cursor streamlog.SourceCursor, audit *cancelledSourceFiles) error {
	if audit == nil || audit.Offset < 0 || audit.FileID == "" || audit.TailBytes != int(min(audit.Offset, int64(streamlog.SourceTailProofBytes))) {
		return streamlog.ErrContentConflict
	}
	f, e := os.Open(cursor.Path)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if realtime.FileIdentity(cursor.Path, info) != audit.FileID || info.Size() < audit.Offset {
		return streamlog.ErrContentConflict
	}
	if audit.TailBytes > 0 {
		tail := make([]byte, audit.TailBytes)
		if _, e = f.ReadAt(tail, audit.Offset-int64(audit.TailBytes)); e != nil {
			return e
		}
		sum := sha256.Sum256(tail)
		if hex.EncodeToString(sum[:]) != audit.TailSHA256 {
			return streamlog.ErrContentConflict
		}
	}
	return nil
}
