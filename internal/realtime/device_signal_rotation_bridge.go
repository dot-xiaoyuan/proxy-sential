package realtime

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxy-sentinel/internal/streamlog"
)

const maxSignalRotationBridgeBytes = 16 << 10

type signalRotationBridgeFile struct {
	Name   string `json:"name"`
	FileID string `json:"file_id"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type signalRotationBridge struct {
	SchemaVersion string                   `json:"schema_version"`
	SourcePath    string                   `json:"source_path"`
	Epoch         string                   `json:"epoch"`
	From          signalRotationBridgeFile `json:"from"`
	To            signalRotationBridgeFile `json:"to"`
}

func isDatedPacketRotation(name string) bool {
	suffix, ok := strings.CutPrefix(name, "ttl.jsonl-")
	if !ok || len(suffix) != len("20060102-150405") {
		return false
	}
	_, err := time.Parse("20060102-150405", suffix)
	return err == nil
}

// Date-based names and numbered names come from different rotation schemes.
// Their ordering must be established before installing this audited edge in
// the existing recovery directory. The cursor still proves its committed tail,
// and the two immutable files must match that audit before crossing the edge.
func verifiedDatedSignalSuccessor(path string, files []signalFile, old signalFile, cursor streamlog.SourceCursor) (signalFile, error) {
	dir := os.Getenv(deviceSignalRecoveryDirEnv)
	if dir == "" || cursor.Epoch == "" || !validSignalTail(cursor) {
		return signalFile{}, ErrStreamSourceGap
	}
	proof, err := readSignalRotationBridge(filepath.Join(dir, "ttl-rotation-bridge.json"))
	if err != nil {
		return signalFile{}, err
	}
	if proof.SchemaVersion != "device-signal-rotation-bridge/v1" || proof.SourcePath != path || proof.Epoch != cursor.Epoch ||
		proof.From.Bytes != cursor.Offset || !proof.From.matches(old) {
		return signalFile{}, ErrStreamSourceGap
	}
	for _, next := range files {
		if !next.protected || !next.compressed || next.chainSeq < 0 || next.id == old.id || !proof.To.matches(next) {
			continue
		}
		return next, nil
	}
	return signalFile{}, ErrStreamSourceGap
}

// SHA256 and byte counts are over the physical files. The archive read also
// verifies the complete gzip stream, including its trailer and final newline.
func (proof signalRotationBridgeFile) matches(file signalFile) bool {
	if proof.Name != filepath.Base(file.path) || proof.FileID != file.id || proof.Bytes <= 0 ||
		proof.Bytes != file.info.Size() || len(proof.SHA256) != 64 {
		return false
	}
	sum, size, ok := hashSignalFile(file, false)
	return ok && size == proof.Bytes && hex.EncodeToString(sum[:]) == proof.SHA256
}

func readSignalRotationBridge(path string) (signalRotationBridge, error) {
	var proof signalRotationBridge
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxSignalRotationBridgeBytes {
		return proof, ErrStreamSourceGap
	}
	f, err := os.Open(path)
	if err != nil {
		return proof, ErrStreamSourceGap
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !os.SameFile(info, before) {
		return proof, ErrStreamSourceGap
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSignalRotationBridgeBytes+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(raw)) != before.Size() || len(raw) > maxSignalRotationBridgeBytes ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || json.Unmarshal(raw, &proof) != nil {
		return signalRotationBridge{}, ErrStreamSourceGap
	}
	return proof, nil
}
