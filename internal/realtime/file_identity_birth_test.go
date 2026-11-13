package realtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/streamlog"
)

func TestFileIdentityBirthSeparatesReusedInode(t *testing.T) {
	first := formatFileIdentity("/signals/ttl.jsonl", 64768, 45887118, "1762760000.123456789")
	second := formatFileIdentity("/signals/ttl.jsonl", 64768, 45887118, "1762790000.123456789")
	if first == second || first == "" || second == "" {
		t.Fatalf("reused inode produced the same file identity: %q %q", first, second)
	}
}

func TestFileIdentityBirthModeUsesFilesystemCreationTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ttl.jsonl")
	if err := os.WriteFile(path, []byte("event\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := fileIdentity(path, info)
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	versioned := fileIdentity(path, info)
	if versioned == "" || versioned == legacy || versioned != fileIdentity(path, info) {
		t.Fatalf("birth-aware identity is missing or unstable: legacy=%q versioned=%q", legacy, versioned)
	}
}

func TestFileIdentityBirthAtKeepsLogicalSourcePath(t *testing.T) {
	dir := t.TempDir()
	logical := filepath.Join(dir, "flow-syn.jsonl")
	protected := filepath.Join(dir, "protected-flow.jsonl")
	if err := os.WriteFile(protected, []byte("event\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(protected)
	if err != nil {
		t.Fatal(err)
	}
	got := FileIdentityBirthAt(logical, protected, info)
	if got == "" || got == FileIdentityBirth(protected, info) || got != fileIdentityBirthAt(logical, protected, info) {
		t.Fatalf("physical birth must be bound to logical source: %q", got)
	}
}

func TestDeviceSignalCaptureRejectsRewrittenCursorTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ttl.jsonl")
	old := []byte("old\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
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
	sum := sha256.Sum256(old)
	source := Source{Kind: "device-signals", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), Offset: int64(len(old)), TailBytes: len(old), TailSHA256: hex.EncodeToString(sum[:]), ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new\nmore\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source)
	if !errors.Is(err, ErrStreamSourceGap) {
		t.Fatalf("rewritten same-inode source must stop before projection: %v", err)
	}
}
