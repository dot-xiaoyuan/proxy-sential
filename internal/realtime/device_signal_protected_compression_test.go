package realtime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/streamlog"
)

func TestProtectedPacketRawAnchorsCrossCompressedNeighbors(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	dir := t.TempDir()
	source := filepath.Join(dir, "ttl.jsonl")
	recovery := filepath.Join(dir, "protected")
	t.Setenv(deviceSignalRecoveryDirEnv, recovery)
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	oldRaw, nextRaw := []byte("old\n"), []byte("next\n")
	old := filepath.Join(recovery, "ttl.jsonl.1")
	next := filepath.Join(recovery, "ttl-live-20261113T1100.jsonl")
	for path, data := range map[string][]byte{old: oldRaw, next: nextRaw, source + ".1": []byte("later\n"), source: []byte("current\n")} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeGzipFixture(t, source+".3.gz", oldRaw)
	writeGzipFixture(t, source+".2.gz", nextRaw)
	if err := os.Link(source+".2.gz", filepath.Join(recovery, "ttl-chain-000000000000.jsonl.gz")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(old)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(oldRaw)
	cursor := streamlog.SourceCursor{FileID: FileIdentityBirthAt(source, old, info), Offset: int64(len(oldRaw)),
		TailBytes: len(oldRaw), TailSHA256: hex.EncodeToString(sum[:])}
	read, err := readDeviceSignalChunk(source, cursor, 1<<20)
	if err != nil || string(read.data) != string(nextRaw) || !read.verifiedRotation {
		t.Fatalf("compressed adjacent successor was not proved: %+v %v", read, err)
	}
}

func TestProtectedPacketCompressedNeighborsRejectGaps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*testing.T, string, string)
	}{
		{"wrong-old-body", func(t *testing.T, source, _ string) { writeGzipFixture(t, source+".3.gz", []byte("wrong\n")) }},
		{"wrong-live-body", func(t *testing.T, source, recovery string) {
			p := filepath.Join(recovery, "ttl-chain-000000000000.jsonl.gz")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			writeGzipFixture(t, source+".2.gz", []byte("wrong\n"))
			if err := os.Link(source+".2.gz", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"nonadjacent", func(t *testing.T, source, _ string) {
			if err := os.Rename(source+".3.gz", source+".4.gz"); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicate-old-match", func(t *testing.T, source, _ string) { writeGzipFixture(t, source+".5.gz", []byte("old\n")) }},
		{"missing-chain", func(t *testing.T, _, recovery string) {
			if err := os.Remove(filepath.Join(recovery, "ttl-chain-000000000000.jsonl.gz")); err != nil {
				t.Fatal(err)
			}
		}},
		{"bad-gzip-crc", func(t *testing.T, source, _ string) {
			p := source + ".3.gz"
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)-1] ^= 0x80
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
			dir := t.TempDir()
			source := filepath.Join(dir, "ttl.jsonl")
			recovery := filepath.Join(dir, "protected")
			t.Setenv(deviceSignalRecoveryDirEnv, recovery)
			if err := os.Mkdir(recovery, 0o700); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(recovery, "ttl.jsonl.1")
			next := filepath.Join(recovery, "ttl-live-20261113T1100.jsonl")
			for path, data := range map[string][]byte{old: []byte("old\n"), next: []byte("next\n"), source + ".1": []byte("later\n"), source: []byte("current\n")} {
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeGzipFixture(t, source+".3.gz", []byte("old\n"))
			writeGzipFixture(t, source+".2.gz", []byte("next\n"))
			if err := os.Link(source+".2.gz", filepath.Join(recovery, "ttl-chain-000000000000.jsonl.gz")); err != nil {
				t.Fatal(err)
			}
			tc.alter(t, source, recovery)
			info, err := os.Stat(old)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte("old\n"))
			cursor := streamlog.SourceCursor{FileID: FileIdentityBirthAt(source, old, info), Offset: int64(len("old\n")),
				TailBytes: len("old\n"), TailSHA256: hex.EncodeToString(sum[:])}
			if _, err := readDeviceSignalChunk(source, cursor, 1<<20); !errors.Is(err, ErrStreamSourceGap) {
				t.Fatalf("unproved compressed successor accepted: %v", err)
			}
		})
	}
}
