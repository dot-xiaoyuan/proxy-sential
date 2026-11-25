package store

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Replacing the contents without renaming preserves Dev:Ino on every test
// filesystem, reproducing the identity seen by the reader after inode reuse.
func TestPassiveArchiveRotations(t *testing.T) {
	prefix := []byte("previous batch\n")
	batch := []byte("first row\r\nsecond row\n")
	wanted := map[string]bool{passiveRawDigest([]byte("first row")): true}
	for _, tc := range []struct {
		name, rotation                string
		reuse, gzip, remove, mismatch bool
	}{
		{name: "rename", rotation: ".1"},
		{name: "inode-reuse", rotation: ".1", reuse: true},
		{name: "compressed-offset", rotation: ".3.gz", gzip: true},
		{name: "missing-current-date-rotation", rotation: "-20261125-080000.gz", gzip: true, remove: true},
		{name: "same-lines-wrong-batch", rotation: ".2.gz", gzip: true, mismatch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "ttl.jsonl")
			original := append(append([]byte{}, prefix...), batch...)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			id := st.Sys().(*syscall.Stat_t)
			src := passiveArchiveSource{Path: path, FileID: fmt.Sprintf("%s:%d:%d", path, id.Dev, id.Ino), Start: int64(len(prefix)), End: int64(len(original)), Digest: passiveRawDigest(batch), Accepted: st.ModTime()}
			got, err := readPassiveArchiveRows(context.Background(), src, []string{root}, "", wanted)
			if err != nil || len(got) != 1 {
				t.Fatalf("original: got %v err %v", got, err)
			}
			if tc.mismatch {
				original[len(original)-2] = '!'
			}
			switch {
			case tc.gzip:
				f, e := os.Create(path + tc.rotation)
				if e != nil {
					t.Fatal(e)
				}
				w := gzip.NewWriter(f)
				if _, e = w.Write(original); e != nil {
					t.Fatal(e)
				}
				if e = w.Close(); e != nil {
					t.Fatal(e)
				}
				if e = f.Close(); e != nil {
					t.Fatal(e)
				}
				if e = os.Remove(path); e != nil {
					t.Fatal(e)
				}
			case tc.reuse:
				if e := os.WriteFile(path+tc.rotation, original, 0600); e != nil {
					t.Fatal(e)
				}
			default:
				if e := os.Rename(path, path+tc.rotation); e != nil {
					t.Fatal(e)
				}
			}
			if !tc.remove {
				if e := os.WriteFile(path, []byte(strings.Repeat("x", len(original))), 0600); e != nil {
					t.Fatal(e)
				}
			}
			got, err = readPassiveArchiveRows(context.Background(), src, []string{root}, "", wanted)
			if tc.mismatch {
				if err == nil || len(got) != 0 {
					t.Fatalf("accepted unmatched batch: %v %v", got, err)
				}
				return
			}
			if err != nil || string(got[passiveRawDigest([]byte("first row"))]) != "first row" {
				t.Fatalf("rotation failed: got %v err %v", got, err)
			}
		})
	}
}

func TestPassiveArchivePreservedRotationsAndBounds(t *testing.T) {
	root, saved := t.TempDir(), t.TempDir()
	path := filepath.Join(root, "ttl.jsonl")
	data := []byte("preserved row\n")
	wanted := map[string]bool{passiveRawDigest([]byte("preserved row")): true}
	src := passiveArchiveSource{Path: path, Start: 0, End: int64(len(data)), Digest: passiveRawDigest(data)}
	write := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(saved, "ttl.jsonl.2"))
	read := func(ctx context.Context, source passiveArchiveSource, preserved string) (map[string][]byte, error) {
		return readPassiveArchiveRows(ctx, source, []string{root}, preserved, wanted)
	}
	found, err := read(context.Background(), src, saved)
	if err != nil || len(found) != 1 {
		t.Fatal("missing preserved original", found, err)
	}
	src.Path = filepath.Join(t.TempDir(), "ttl.jsonl")
	if _, err = read(context.Background(), src, saved); err == nil {
		t.Fatal("accepted unregistered original path")
	}
	src.Path = path
	if _, err = read(context.Background(), src, "relative"); err == nil {
		t.Fatal("accepted relative recovery path")
	}
	outside := filepath.Join(t.TempDir(), "stolen")
	write(outside)
	if err := os.Symlink(outside, path+".1"); err != nil {
		t.Fatal(err)
	}
	write(path + ".tmp")
	if _, err = read(context.Background(), src, ""); err == nil {
		t.Fatal("accepted unrelated or escaping file")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = read(cancelled, src, saved); !errors.Is(err, context.Canceled) {
		t.Fatalf("ignored cancellation: %v", err)
	}
	src.End = src.Start + passiveArchiveBatchBytes + 1
	if _, err = read(context.Background(), src, saved); err == nil {
		t.Fatal("unbounded batch")
	}
	src.End = passiveArchiveGzipOutputBudget + 100
	src.Start = src.End - int64(len(data))
	write(path + ".4.gz")
	if _, err = read(context.Background(), src, ""); !errors.Is(err, errPassiveArchiveBudget) {
		t.Fatalf("unbounded inflation: %v", err)
	}
}

func TestPassiveArchiveRotationCountBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.log")
	for n := 1; n <= passiveArchiveMaxRotations+1; n++ {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", path, n), []byte("xx"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	source := passiveArchiveSource{Path: path, Start: 0, End: 1, Digest: passiveRawDigest([]byte("y"))}
	if _, err := readPassiveArchiveRows(context.Background(), source, []string{dir}, "", map[string]bool{}); !errors.Is(err, errPassiveArchiveBudget) {
		t.Fatalf("unreported candidate truncation: %v", err)
	}
}

func TestPassiveArchiveLineTerminatorDoesNotInventEmptyRecord(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ttl.jsonl")
	empty := passiveRawDigest(nil)
	for _, tc := range []struct {
		data     string
		hasEmpty bool
	}{{"row\r\n", false}, {"row\r\n\r\n", true}, {"row", false}} {
		if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
			t.Fatal(err)
		}
		src := passiveArchiveSource{Path: path, End: int64(len(tc.data)), Digest: passiveRawDigest([]byte(tc.data))}
		rows, err := readPassiveArchiveRows(context.Background(), src, []string{root}, "", map[string]bool{empty: true})
		_, ok := rows[empty]
		if err != nil || ok != tc.hasEmpty {
			t.Fatalf("batch %q returned empty=%t, error=%v", tc.data, ok, err)
		}
	}
}
