package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	passiveArchiveMaxDirectoryEntries = 4096
	passiveArchiveMaxRotations        = 32
	passiveArchiveGzipInputBudget     = 512 << 20
	passiveArchiveGzipOutputBudget    = 2 << 30
)

var (
	// logrotate numbering and dateext (-YYYYMMDD or -YYYYMMDD-HHMMSS).
	passiveRotationSuffix   = regexp.MustCompile(`^(?:\.[1-9][0-9]{0,5}|-[0-9]{8}(?:-[0-9]{6})?)(?:\.gz)?$`)
	errPassiveArchiveBudget = errors.New("rotation search budget reached")
	errPassiveArchiveDigest = errors.New("batch digest mismatch")
)

type passiveArchiveCandidate struct {
	root       *os.Root
	path       string
	inodeMatch bool
	distance   time.Duration
}

type passiveArchiveSearch struct {
	ctx                              context.Context
	compressedLeft, uncompressedLeft int64
	data                             []byte
}

type passiveArchiveLimitedReader struct {
	reader io.Reader
	ctx    context.Context
	left   *int64
}

// Check cancellation during decompression, including a gzip full of empty
// members. Input and expanded bytes are shared across the entire search.
func (r passiveArchiveLimitedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if *r.left == 0 {
		return 0, errPassiveArchiveBudget
	}
	n, err := r.reader.Read(p[:min(int64(len(p)), *r.left, 64<<10)])
	*r.left -= int64(n)
	return n, err
}

func (s *passiveArchiveSearch) read(source passiveArchiveSource, root *os.Root, path string) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	// Opening a FIFO nonblocking avoids stalling if the entry changes between
	// enumeration and open. OpenRoot also confines symlink traversal.
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file")
	}
	if strings.HasSuffix(path, ".gz") {
		if source.End > s.uncompressedLeft {
			return errPassiveArchiveBudget
		}
		zr, err := gzip.NewReader(passiveArchiveLimitedReader{f, s.ctx, &s.compressedLeft})
		if err != nil {
			return err
		}
		defer zr.Close()
		input := passiveArchiveLimitedReader{zr, s.ctx, &s.uncompressedLeft}
		if _, err = io.CopyN(io.Discard, input, source.Start); err != nil {
			return err
		}
		if _, err = io.ReadFull(input, s.data); err != nil {
			return err
		}
	} else {
		if st.Size() < source.End {
			return io.ErrUnexpectedEOF
		}
		if _, err = f.ReadAt(s.data, source.Start); err != nil {
			return err
		}
	}
	if passiveRawDigest(s.data) != source.Digest {
		return errPassiveArchiveDigest
	}
	return nil
}

func passiveArchiveFileCandidates(ctx context.Context, root *os.Root, rel string, source passiveArchiveSource) ([]passiveArchiveCandidate, error) {
	parent, name := filepath.Dir(rel), filepath.Base(rel)
	dir, err := root.OpenFile(parent, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var candidates []passiveArchiveCandidate
	// Limit enumeration before sorting even when the log directory is shared.
	for scanned := 0; ; {
		if err := ctx.Err(); err != nil {
			return candidates, err
		}
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			scanned++
			if scanned > passiveArchiveMaxDirectoryEntries {
				return candidates, errPassiveArchiveBudget
			}
			suffix := strings.TrimPrefix(entry.Name(), name)
			if suffix == entry.Name() || !passiveRotationSuffix.MatchString(suffix) || !entry.Type().IsRegular() {
				continue
			}
			if len(candidates) >= passiveArchiveMaxRotations {
				return candidates, errPassiveArchiveBudget
			}
			path := filepath.Join(parent, entry.Name())
			info, e := root.Stat(path)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return candidates, e
			}
			match := false
			if id, ok := info.Sys().(*syscall.Stat_t); ok {
				match = fmt.Sprintf("%s:%d:%d", source.Path, id.Dev, id.Ino) == source.FileID
			}
			candidates = append(candidates, passiveArchiveCandidate{root, path, match, info.ModTime().Sub(source.Accepted).Abs()})
		}
		if readErr == io.EOF {
			return candidates, nil
		}
		if readErr != nil {
			return candidates, readErr
		}
	}
}

// Accept only the committed range's SHA-256, then hash individual raw lines.
// Inode and mtime prioritize candidates; rotation and compression can change both.
func readPassiveArchiveRows(ctx context.Context, source passiveArchiveSource, roots []string, recoveryDir string, wanted map[string]bool) (map[string][]byte, error) {
	size := source.End - source.Start
	if source.Start < 0 || source.End <= source.Start || size > passiveArchiveBatchBytes {
		return nil, fmt.Errorf("source byte range outside archive budget")
	}
	digest, err := hex.DecodeString(source.Digest)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid committed batch digest")
	}
	var captureRoot, rel string
	for _, root := range roots {
		part, err := filepath.Rel(root, source.Path)
		if err == nil && filepath.IsLocal(part) && part != "." {
			captureRoot, rel = root, part
			break
		}
	}
	if captureRoot == "" {
		return nil, fmt.Errorf("source outside archive capture directories")
	}
	if recoveryDir != "" && !filepath.IsAbs(recoveryDir) {
		return nil, fmt.Errorf("rotation recovery directory must be absolute")
	}
	// The worker has 12 seconds including the PG receipt and CH reread. Leave
	// time to persist failures instead of rolling back the same job indefinitely.
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	search := passiveArchiveSearch{readCtx, passiveArchiveGzipInputBudget, passiveArchiveGzipOutputBudget, make([]byte, size)}
	found := func() (map[string][]byte, error) {
		rows := map[string][]byte{}
		// A trailing LF terminates the last record; it does not create a new empty row.
		batch := bytes.TrimSuffix(search.data, []byte("\n"))
		for line := range bytes.SplitSeq(batch, []byte("\n")) {
			if err := readCtx.Err(); err != nil {
				return nil, err
			}
			line = bytes.TrimSuffix(line, []byte("\r"))
			h := passiveRawDigest(line)
			if wanted[h] {
				rows[h] = line
				if len(rows) == len(wanted) {
					break
				}
			}
		}
		return rows, nil
	}
	var candidates []passiveArchiveCandidate
	var incomplete error
	var lastErr error
	locations := []struct{ root, path string }{{captureRoot, rel}}
	if recoveryDir != "" {
		locations = append(locations, struct{ root, path string }{recoveryDir, filepath.Base(rel)})
	}
	for i, loc := range locations {
		root, e := os.OpenRoot(loc.root)
		if e != nil {
			incomplete = e
			continue
		}
		defer root.Close()
		if i == 0 {
			lastErr = search.read(source, root, loc.path)
			if lastErr == nil {
				return found()
			}
			if !errors.Is(lastErr, os.ErrNotExist) && !errors.Is(lastErr, io.ErrUnexpectedEOF) && !errors.Is(lastErr, errPassiveArchiveDigest) {
				incomplete = lastErr
			}
		}
		tail, e := passiveArchiveFileCandidates(readCtx, root, loc.path, source)
		candidates = append(candidates, tail...)
		if e != nil {
			incomplete = e
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.inodeMatch != b.inodeMatch {
			return a.inodeMatch
		}
		plainA, plainB := !strings.HasSuffix(a.path, ".gz"), !strings.HasSuffix(b.path, ".gz")
		if plainA != plainB {
			return plainA
		}
		return a.distance < b.distance
	})
	for _, candidate := range candidates {
		if err := readCtx.Err(); err != nil {
			return nil, fmt.Errorf("rotation search incomplete: %w", err)
		}
		lastErr = search.read(source, candidate.root, candidate.path)
		if lastErr == nil {
			return found()
		}
		if !errors.Is(lastErr, io.EOF) && !errors.Is(lastErr, io.ErrUnexpectedEOF) && !errors.Is(lastErr, errPassiveArchiveDigest) {
			incomplete = lastErr
		}
	}
	if incomplete != nil {
		return nil, fmt.Errorf("rotation search incomplete (%d rotation candidates): %w", len(candidates), incomplete)
	}
	return nil, fmt.Errorf("no verified source byte range [%d,%d) in current or %d rotation candidates: %w", source.Start, source.End, len(candidates), lastErr)
}
