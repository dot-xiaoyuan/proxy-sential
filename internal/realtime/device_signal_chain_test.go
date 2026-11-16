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

func TestProtectedDeviceSignalChainAdvancesOnlyAcrossVerifiedSuccessors(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "ttl.jsonl")
	recovery := filepath.Join(dir, "protected")
	t.Setenv(deviceSignalRecoveryDirEnv, recovery)
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(recovery, "ttl-live-20261113T1100.jsonl")
	if err := os.WriteFile(live, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chain0 := filepath.Join(recovery, "ttl-chain-000000000000.jsonl.gz")
	chain1 := filepath.Join(recovery, "ttl-chain-000000000001.jsonl.gz")
	chain2 := filepath.Join(recovery, "ttl-chain-000000000002.jsonl.gz")
	writeGzipFixture(t, chain0, []byte("first\n"))
	writeGzipFixture(t, chain1, []byte("second\n"))
	writeGzipFixture(t, chain2, []byte("third\n"))

	files, err := deviceSignalFiles(source)
	if err != nil {
		t.Fatal(err)
	}
	find := func(path string) signalFile {
		t.Helper()
		for _, file := range files {
			if file.path == path {
				return file
			}
		}
		t.Fatalf("file not discovered: %s", path)
		return signalFile{}
	}
	if next, err := nextSignalFile(source, files, find(live)); err != nil || next.path != chain1 {
		t.Fatalf("initial successor: %+v %v", next, err)
	}
	if next, err := nextSignalFile(source, files, find(chain1)); err != nil || next.path != chain2 {
		t.Fatalf("later successor: %+v %v", next, err)
	}
	first := []byte("first\n")
	firstHash := sha256.Sum256(first)
	cursor := streamlog.SourceCursor{FileID: find(live).id, Offset: int64(len(first)), TailBytes: len(first), TailSHA256: hex.EncodeToString(firstHash[:])}
	for _, want := range []string{"second\n", "third\n"} {
		read, err := readDeviceSignalChunk(source, cursor, 1024)
		if err != nil || !read.verifiedRotation || string(read.data) != want {
			t.Fatalf("read protected successor: got %q verified=%t err=%v", read.data, read.verifiedRotation, err)
		}
		dataHash := sha256.Sum256(read.data)
		cursor = streamlog.SourceCursor{FileID: read.fileID, Offset: read.end, TailBytes: len(read.data), TailSHA256: hex.EncodeToString(dataHash[:])}
	}
	if err := os.Remove(chain0); err != nil {
		t.Fatal(err)
	}
	clearSignalGzip(source)
	files, err = deviceSignalFiles(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nextSignalFile(source, files, find(live)); !errors.Is(err, ErrStreamSourceGap) {
		t.Fatalf("missing first proof was accepted: %v", err)
	}
}

func TestProtectedHandshakeChainResumesAfterDateArchiveRecovery(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "handshake.jsonl")
	recovery := filepath.Join(dir, "protected")
	t.Setenv(deviceSignalRecoveryDirEnv, recovery)
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		source: []byte("current\n"),
		filepath.Join(recovery, "handshake-live-start.jsonl"): []byte("old\n"),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	chain0 := filepath.Join(recovery, "handshake-chain-000000000000.jsonl.gz")
	chain1 := filepath.Join(recovery, "handshake-chain-000000000001.jsonl.gz")
	writeGzipFixture(t, chain0, []byte("old\n"))
	writeGzipFixture(t, chain1, []byte("next\n"))
	old := []byte("old\n")
	sum := sha256.Sum256(old)
	live := filepath.Join(recovery, "handshake-live-start.jsonl")
	info, err := os.Stat(live)
	if err != nil {
		t.Fatal(err)
	}
	cursor := streamlog.SourceCursor{FileID: FileIdentityBirthAt(source, live, info), Offset: int64(len(old)), TailBytes: len(old), TailSHA256: hex.EncodeToString(sum[:])}
	read, err := readDeviceSignalChunk(source, cursor, 1024)
	if err != nil || !read.verifiedRotation || string(read.data) != "next\n" {
		t.Fatalf("handshake successor was not recovered: %+v %v", read, err)
	}
	if err := os.Remove(chain0); err != nil {
		t.Fatal(err)
	}
	clearSignalGzip(source)
	if _, err := readDeviceSignalChunk(source, cursor, 1024); !errors.Is(err, ErrStreamSourceGap) {
		t.Fatalf("handshake successor without first chain proof was accepted: %v", err)
	}
}
