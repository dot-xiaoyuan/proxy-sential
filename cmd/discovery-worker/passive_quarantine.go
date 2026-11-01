package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"proxy-sentinel/internal/streamlog"
)

type passiveQuarantineRecord struct {
	SegmentID     string                         `json:"segment_id"`
	ContentSHA256 string                         `json:"content_sha256"`
	RawSHA256     string                         `json:"raw_sha256"`
	Epoch         string                         `json:"epoch"`
	SourcePath    string                         `json:"source_path"`
	Reason        string                         `json:"reason"`
	Status        string                         `json:"status"`
	RecordedAt    time.Time                      `json:"recorded_at"`
	WALReference  *streamlog.PassiveWALReference `json:"wal_reference,omitempty"`
}

type passiveQuarantineJournal interface {
	Load(string) (streamlog.State, error)
}

// A deterministic scope conflict stops the live lane and creates an
// independently visible audit record. The immutable journal segment is hard
// linked, retaining one raw body until an operator resolves the gap.
func quarantinePassiveSegment(journal passiveQuarantineJournal, journalDir, spool, id string, cause error) (string, error) {
	if journal == nil || id == "" || filepath.Base(id) != id || spool == "" || journalDir == "" || cause == nil {
		return "", errors.New("invalid passive quarantine request")
	}
	state, err := journal.Load(id)
	if err != nil {
		return "", fmt.Errorf("load failed passive segment: %w", err)
	}
	if state.Released || !state.Committed || state.Segment.Source != "passive-discovery" {
		return "", errors.New("passive segment is not an unreleased committed source")
	}
	dir := filepath.Join(spool, "discovery-quarantine")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	record := passiveQuarantineRecord{SegmentID: id, ContentSHA256: state.ContentSHA256,
		RawSHA256: state.Segment.RawSHA256, Epoch: state.Segment.Epoch,
		SourcePath: state.Segment.SourcePath, Reason: cause.Error(),
		Status: "quarantined_unprocessed", RecordedAt: time.Now().UTC()}
	if len(record.Reason) > 512 {
		record.Reason = record.Reason[:512]
	}
	if wal, ok := journal.(*streamlog.PassiveWALJournal); ok {
		if ref, exists := wal.V2SegmentReference(id); exists {
			// Seal the failure before publishing its external diagnostic record.
			// A crash between these steps still pins the body and stops capture.
			if err := wal.Quarantine(id, record.Reason); err != nil {
				return "", fmt.Errorf("quarantine passive WAL segment: %w", err)
			}
			record.WALReference = &ref
		}
	}
	if record.WALReference == nil {
		source := filepath.Join(journalDir, id+".segment")
		target := filepath.Join(dir, id+".segment")
		if err := os.Link(source, target); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return "", fmt.Errorf("link immutable passive segment: %w", err)
			}
			oldInfo, oldErr := os.Stat(source)
			newInfo, newErr := os.Stat(target)
			if oldErr != nil || newErr != nil || !os.SameFile(oldInfo, newInfo) {
				return "", errors.New("quarantine segment path contains different content")
			}
		}
	}
	path := filepath.Join(dir, id+".json")
	validatePrior := func() (string, error) {
		var prior passiveQuarantineRecord
		raw, readErr := os.ReadFile(path)
		if readErr != nil || json.Unmarshal(raw, &prior) != nil || prior.SegmentID != id ||
			prior.ContentSHA256 != record.ContentSHA256 || prior.RawSHA256 != record.RawSHA256 ||
			prior.Epoch != record.Epoch || prior.Status != record.Status {
			return "", errors.New("quarantine manifest conflicts with immutable segment")
		}
		if (prior.WALReference == nil) != (record.WALReference == nil) ||
			(prior.WALReference != nil && *prior.WALReference != *record.WALReference) {
			return "", errors.New("quarantine manifest conflicts with WAL reference")
		}
		return path, nil
	}
	if _, err := os.Stat(path); err == nil {
		return validatePrior()
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	f, err := os.CreateTemp(dir, id+".tmp-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return "", err
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err == nil {
		_, err = f.Write(encoded)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	// Linking a fully synced temporary file publishes the complete manifest
	// without replacing a manifest another worker may have created first.
	if err := os.Link(f.Name(), path); errors.Is(err, os.ErrExist) {
		return validatePrior()
	} else if err != nil {
		return "", err
	}
	d, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	err = d.Sync()
	_ = d.Close()
	if err != nil {
		return "", err
	}
	return path, nil
}
