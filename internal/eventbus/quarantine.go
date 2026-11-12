package eventbus

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type quarantinedRecord struct {
	Topic         string    `json:"topic"`
	Partition     int32     `json:"partition"`
	Offset        int64     `json:"offset"`
	ContentSHA256 string    `json:"content_sha256"`
	PayloadBase64 string    `json:"payload_base64"`
	Reason        string    `json:"reason"`
	QuarantinedAt time.Time `json:"quarantined_at"`
}

// quarantineInvalidRecord persists an unparseable record before its Kafka
// offset may be committed. The position is the immutable key; a different
// payload at the same position is a hard conflict.
func quarantineInvalidRecord(dir string, record *kgo.Record, reason string) (string, error) {
	if dir == "" || record == nil {
		return "", errors.New("event bus quarantine directory and record are required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	topicHash := sha256.Sum256([]byte(record.Topic))
	contentHash := sha256.Sum256(record.Value)
	path := filepath.Join(dir, fmt.Sprintf("%x-%d-%020d.json", topicHash[:8], record.Partition, record.Offset))
	value := quarantinedRecord{
		Topic: record.Topic, Partition: record.Partition, Offset: record.Offset,
		ContentSHA256: hex.EncodeToString(contentHash[:]), PayloadBase64: base64.StdEncoding.EncodeToString(record.Value),
		Reason: reason, QuarantinedAt: time.Now().UTC(),
	}
	checkExisting := func() (string, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		var existing quarantinedRecord
		if err := json.Unmarshal(raw, &existing); err != nil {
			return "", err
		}
		if existing.Topic != value.Topic || existing.Partition != value.Partition || existing.Offset != value.Offset ||
			existing.ContentSHA256 != value.ContentSHA256 || existing.PayloadBase64 != value.PayloadBase64 {
			return "", errors.New("event bus quarantine position has conflicting content")
		}
		return path, nil
	}
	if _, err := os.Stat(path); err == nil {
		return checkExisting()
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	temp, err := os.CreateTemp(dir, ".quarantine-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return "", err
	}
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := os.Link(temp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return checkExisting()
		}
		return "", err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return "", err
	}
	return path, nil
}

const maxReplayFiles = 32
const maxQuarantineFileBytes = 12 << 20

// ReplayResult is a durable per-position result. The original quarantine file
// remains in place; a separate immutable audit proves a particular sink mode
// returned success before this result was reported.
type ReplayResult struct {
	File          string `json:"file"`
	Status        string `json:"status"`
	Mode          string `json:"mode"`
	Topic         string `json:"topic"`
	Partition     int32  `json:"partition"`
	Offset        int64  `json:"offset"`
	ContentSHA256 string `json:"content_sha256"`
	EventID       string `json:"event_id"`
	AuditPath     string `json:"audit_path"`
}

type replayAudit struct {
	Mode          string    `json:"mode"`
	Topic         string    `json:"topic"`
	Partition     int32     `json:"partition"`
	Offset        int64     `json:"offset"`
	ContentSHA256 string    `json:"content_sha256"`
	EventID       string    `json:"event_id"`
	AppliedAt     time.Time `json:"applied_at"`
}

// ReplayQuarantinedRecords replays explicitly named positions, one at a time.
// It never commits a Kafka offset. A failed sink or audit leaves the original
// file for another attempt; the sink must itself be idempotent on replay.
func ReplayQuarantinedRecords(ctx context.Context, dir, topic, mode string, names []string, sink ReceiptSink) ([]ReplayResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if dir == "" || topic == "" || (mode != "normalized-only" && mode != "full") || sink == nil || len(names) < 1 || len(names) > maxReplayFiles {
		return nil, errors.New("event bus replay requires directory, topic, sink mode, sink and 1..32 explicit files")
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if name == "" || name != filepath.Base(name) || !strings.HasSuffix(name, ".json") || seen[name] {
			return nil, fmt.Errorf("invalid or duplicate quarantine file %q", name)
		}
		seen[name] = true
	}
	results := make([]ReplayResult, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		path := filepath.Join(dir, name)
		entry, record, err := readQuarantineRecord(path, name, topic)
		if err != nil {
			return results, fmt.Errorf("quarantine %s: %w", name, err)
		}
		receipt, err := receiptFromRecord(record)
		if err != nil {
			return results, fmt.Errorf("quarantine %s remains invalid: %w", name, err)
		}
		auditPath := path + ".replay." + mode + ".json"
		lock, err := os.OpenFile(path+".replay.lock", os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return results, err
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			lock.Close()
			return results, fmt.Errorf("quarantine %s is already replaying: %w", name, err)
		}
		result := ReplayResult{File: name, Mode: mode, Topic: entry.Topic, Partition: entry.Partition, Offset: entry.Offset,
			ContentSHA256: entry.ContentSHA256, EventID: receipt.EventID, AuditPath: auditPath}
		applyErr := func() error {
			defer lock.Close()
			if existing, err := os.ReadFile(auditPath); err == nil {
				var audit replayAudit
				if json.Unmarshal(existing, &audit) != nil || !auditMatches(audit, entry, mode, receipt.EventID) {
					return errors.New("replay audit conflicts with quarantine position")
				}
				result.Status = "already_applied"
				return nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := sink.WriteReceipts(ctx, []Receipt{receipt}); err != nil {
				return err
			}
			audit := replayAudit{Mode: mode, Topic: entry.Topic, Partition: entry.Partition, Offset: entry.Offset,
				ContentSHA256: entry.ContentSHA256, EventID: receipt.EventID, AppliedAt: time.Now().UTC()}
			if err := persistReplayAudit(dir, auditPath, audit); err != nil {
				return err
			}
			result.Status = "applied"
			return nil
		}()
		if applyErr != nil {
			return results, fmt.Errorf("replay %s: %w", name, applyErr)
		}
		results = append(results, result)
	}
	return results, nil
}

func readQuarantineRecord(path, name, expectedTopic string) (quarantinedRecord, *kgo.Record, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return quarantinedRecord{}, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxQuarantineFileBytes {
		return quarantinedRecord{}, nil, errors.New("quarantine file is not a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return quarantinedRecord{}, nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxQuarantineFileBytes+1))
	if err != nil {
		return quarantinedRecord{}, nil, err
	}
	if len(raw) > maxQuarantineFileBytes {
		return quarantinedRecord{}, nil, errors.New("quarantine file exceeds replay byte limit")
	}
	var entry quarantinedRecord
	if err := json.Unmarshal(raw, &entry); err != nil {
		return quarantinedRecord{}, nil, err
	}
	if entry.Topic != expectedTopic || entry.Partition < 0 || entry.Offset < 0 || entry.Reason == "" || entry.QuarantinedAt.IsZero() {
		return quarantinedRecord{}, nil, errors.New("quarantine topic, offset or original reason is invalid")
	}
	topicHash := sha256.Sum256([]byte(entry.Topic))
	wantName := fmt.Sprintf("%x-%d-%020d.json", topicHash[:8], entry.Partition, entry.Offset)
	if name != wantName {
		return quarantinedRecord{}, nil, errors.New("quarantine file name disagrees with source position")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(entry.PayloadBase64)
	if err != nil {
		return quarantinedRecord{}, nil, err
	}
	hash := sha256.Sum256(payload)
	if entry.ContentSHA256 != hex.EncodeToString(hash[:]) {
		return quarantinedRecord{}, nil, errors.New("quarantine payload hash mismatch")
	}
	return entry, &kgo.Record{Topic: entry.Topic, Partition: entry.Partition, Offset: entry.Offset, Value: payload}, nil
}

func auditMatches(a replayAudit, q quarantinedRecord, mode, eventID string) bool {
	return a.Mode == mode && a.Topic == q.Topic && a.Partition == q.Partition && a.Offset == q.Offset &&
		a.ContentSHA256 == q.ContentSHA256 && a.EventID == eventID && !a.AppliedAt.IsZero()
}

func persistReplayAudit(dir, path string, audit replayAudit) error {
	raw, err := json.Marshal(audit)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".replay-audit-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(temp.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
