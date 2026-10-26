package streamlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

var ErrSourceAlreadyStarted = errors.New("stream source already has a different epoch or fresh position")

type SourceCursor struct {
	Epoch                 string    `json:"epoch"`
	Source                string    `json:"source"`
	Path                  string    `json:"path"`
	FileID                string    `json:"file_id"`
	Offset                int64     `json:"offset"`
	DiscardedBeforeOffset int64     `json:"discarded_before_offset"`
	ParserVersion         string    `json:"parser_version"`
	KeyScheme             string    `json:"key_scheme,omitempty"`
	Generation            uint64    `json:"generation,omitempty"`
	StartedAt             time.Time `json:"started_at"`
	LastSegmentID         string    `json:"last_segment_id,omitempty"`
	TailBytes             int       `json:"tail_bytes,omitempty"`
	TailSHA256            string    `json:"tail_sha256,omitempty"`
}

const SourceTailProofBytes = 4096

func sourceCursorID(source, path string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + path))
	return hex.EncodeToString(sum[:])
}

func (j *Journal) sourcePath(source, path string) string {
	return j.path(sourceCursorID(source, path), ".cursor")
}

func (j *Journal) AcquireSourceLease(source, path string) (func(), error) {
	if source == "" || path == "" {
		return nil, errors.New("stream source lease requires kind and path")
	}
	f, err := os.OpenFile(j.path(sourceCursorID(source, path), ".lease"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stream source already has a reader: %w", err)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }) }, nil
}

func (j *Journal) LoadSource(source, path string) (SourceCursor, error) {
	return j.loadSource(source, path)
}

// SetSourceTailProof seals a legacy cursor's last committed bytes before a
// Zeek rotation. It never changes the source position or the accepted input.
func (j *Journal) SetSourceTailProof(source, path, fileID string, offset int64, raw []byte) error {
	if len(raw) == 0 || len(raw) > SourceTailProofBytes || int64(len(raw)) > offset {
		return ErrContentConflict
	}
	lock, err := j.lockFile(".cursor-lock-" + sourceCursorID(source, path))
	if err != nil {
		return err
	}
	defer unlock(lock)
	cursor, err := j.loadSource(source, path)
	if err != nil {
		return err
	}
	if cursor.FileID != fileID || cursor.Offset != offset {
		return ErrContentConflict
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	if cursor.TailBytes != 0 {
		if cursor.TailBytes == len(raw) && cursor.TailSHA256 == hash {
			return nil
		}
		return ErrContentConflict
	}
	cursor.TailBytes, cursor.TailSHA256 = len(raw), hash
	return atomicJSON(j.sourcePath(source, path), cursor)
}

func (j *Journal) loadSource(source, path string) (SourceCursor, error) {
	var cursor SourceCursor
	data, err := os.ReadFile(j.sourcePath(source, path))
	if err != nil {
		return cursor, err
	}
	if err := json.Unmarshal(data, &cursor); err != nil {
		return cursor, err
	}
	if cursor.Source != source || cursor.Path != path {
		return SourceCursor{}, ErrContentConflict
	}
	return cursor, nil
}

// StartFreshSource records the audited fresh position before any new read. It
// cannot silently change an existing epoch. The caller records the skipped old
// range in the cancellation ledger before starting this source.
func (j *Journal) StartFreshSource(cursor SourceCursor) error {
	if cursor.Epoch == "" || cursor.Source == "" || cursor.Path == "" || cursor.FileID == "" || cursor.ParserVersion == "" || cursor.Offset < 0 {
		return errors.New("fresh stream source requires fixed epoch, path, file, parser and offset")
	}
	if (cursor.TailBytes == 0) != (cursor.TailSHA256 == "") || cursor.TailBytes < 0 || cursor.TailBytes > SourceTailProofBytes || int64(cursor.TailBytes) > cursor.Offset || (cursor.TailBytes > 0 && len(cursor.TailSHA256) != 64) {
		return ErrContentConflict
	}
	if (cursor.KeyScheme == "generation-v2" && (cursor.Source != "zeek-dhcp-binding" || cursor.ParserVersion != "zeek-dhcp-binding-v2" || cursor.Generation == 0)) ||
		(cursor.KeyScheme != "generation-v2" && (cursor.KeyScheme != "" || cursor.Generation != 0)) {
		return ErrContentConflict
	}
	lock, err := j.lockFile(".cursor-lock-" + sourceCursorID(cursor.Source, cursor.Path))
	if err != nil {
		return err
	}
	defer unlock(lock)
	old, err := j.loadSource(cursor.Source, cursor.Path)
	if err == nil {
		if old.Epoch == cursor.Epoch && old.FileID == cursor.FileID && old.DiscardedBeforeOffset == cursor.Offset && old.ParserVersion == cursor.ParserVersion && old.KeyScheme == cursor.KeyScheme && old.Generation == cursor.Generation {
			return nil
		}
		return ErrSourceAlreadyStarted
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cursor.DiscardedBeforeOffset = cursor.Offset
	if cursor.StartedAt.IsZero() {
		cursor.StartedAt = time.Now().UTC()
	}
	return atomicJSON(j.sourcePath(cursor.Source, cursor.Path), cursor)
}

// PrepareSource makes the durable segment eligible for independent sink lanes
// while the source cursor is still at its predecessor. A crash can recover the
// cursor from this body and preserve any sink acknowledgements already written.
func (j *Journal) PrepareSource(source, path, segmentID string) error {
	lock, err := j.lockFile(".cursor-lock-" + sourceCursorID(source, path))
	if err != nil {
		return err
	}
	defer unlock(lock)
	cursor, err := j.loadSource(source, path)
	if err != nil {
		return err
	}
	segmentLock, err := j.lockSegment(segmentID)
	if err != nil {
		return err
	}
	defer unlock(segmentLock)
	state, err := j.load(segmentID)
	if err != nil {
		return err
	}
	if state.Released {
		return ErrContentConflict
	}
	segment := state.Segment
	if err := validateSourceSegment(cursor, segment, source, path); err != nil {
		return err
	}
	if state.ProcessingReady {
		return syncDir(j.dir)
	}
	if state.Committed {
		return nil
	}
	if err := j.prepareEmptyAckLog(segmentID); err != nil {
		return err
	}
	state.ProcessingReady, state.AckLog, state.AckLogSealed = true, true, true
	return atomicJSON(j.path(segmentID, ".state"), stateWithoutEvents(state))
}

func validateSourceSegment(cursor SourceCursor, segment Segment, source, path string) error {
	if segment.Quarantined {
		return ErrQuarantined
	}
	if segment.Epoch != cursor.Epoch || segment.Source != source || segment.SourcePath != path || segment.ParserVersion != cursor.ParserVersion || segment.KeyScheme != cursor.KeyScheme || segment.PreviousGeneration != cursor.Generation || segment.EndOffset <= segment.StartOffset {
		return ErrContentConflict
	}
	if segment.PreviousFileID != cursor.FileID || segment.PreviousOffset != cursor.Offset {
		return fmt.Errorf("stream source predecessor does not match current cursor: %w", ErrContentConflict)
	}
	if cursor.KeyScheme == "generation-v2" {
		switch {
		case segment.SourceGeneration == cursor.Generation && segment.FileID == cursor.FileID && segment.StartOffset == cursor.Offset:
		case segment.SourceGeneration == cursor.Generation+1 && segment.StartOffset == 0:
		default:
			return fmt.Errorf("stream source generation gap or overlap: %w", ErrContentConflict)
		}
	} else {
		if segment.SourceGeneration != 0 {
			return ErrContentConflict
		}
		if segment.FileID == cursor.FileID {
			if segment.StartOffset != cursor.Offset {
				return fmt.Errorf("stream source cursor gap or overlap: %w", ErrContentConflict)
			}
		} else if segment.StartOffset != 0 {
			return fmt.Errorf("stream rotated file must start at zero: %w", ErrContentConflict)
		}
	}
	return nil
}

// AppendSourceReady proves the source predecessor before the immutable body is
// written. Inline standard-event bytes or a verified Zeek source reference
// make the durable descriptor a readiness marker, so sink lanes can start
// without a second producer-side state fsync. Release still waits for the
// durable cursor and all sink acknowledgements.
func (j *Journal) AppendSourceReady(segment Segment) (string, error) {
	inline := segment.RawIsStandardEvents && (segment.Source == "device-signals" || segment.Source == "shared-device-signals")
	verifiedSource := segment.Source == "zeek-dhcp-binding" && segment.SourceBackedRaw
	if !inline && !verifiedSource {
		return "", ErrContentConflict
	}
	lock, err := j.lockFile(".cursor-lock-" + sourceCursorID(segment.Source, segment.SourcePath))
	if err != nil {
		return "", err
	}
	defer unlock(lock)
	cursor, err := j.loadSource(segment.Source, segment.SourcePath)
	if err != nil {
		return "", err
	}
	if err := validateSourceSegment(cursor, segment, segment.Source, segment.SourcePath); err != nil {
		return "", err
	}
	segment.EarlyProcessing = true
	return j.append(segment, true)
}

// CommitSource moves the read cursor only after the matching immutable segment
// is durably present. Consumers own independent acknowledgement positions.
func (j *Journal) CommitSource(source, path, segmentID string) error {
	lock, err := j.lockFile(".cursor-lock-" + sourceCursorID(source, path))
	if err != nil {
		return err
	}
	defer unlock(lock)
	cursor, err := j.loadSource(source, path)
	if err != nil {
		return err
	}
	if cursor.LastSegmentID == segmentID {
		// A prior cursor rename may have succeeded while its directory sync
		// returned an error. Seal it before the segment can be released.
		if err := syncDir(j.dir); err != nil {
			return err
		}
		return j.finishPreparedSource(segmentID, true)
	}
	segmentLock, err := j.lockSegment(segmentID)
	if err != nil {
		return err
	}
	defer func() {
		if segmentLock != nil {
			unlock(segmentLock)
		}
	}()
	state, err := j.load(segmentID)
	if err != nil {
		return err
	}
	if state.Released {
		return ErrContentConflict
	}
	segment := state.Segment
	if err := validateSourceSegment(cursor, segment, source, path); err != nil {
		return err
	}
	// Mark the immutable segment eligible before moving the cursor. A crash
	// between these two durable writes can replay this exact predecessor;
	// moving the cursor first could leave an eligible segment unmarked forever.
	if !state.Committed && !state.ProcessingReady {
		// The empty file's data is synced here; the cursor's directory sync
		// seals its entry together with the compact state rename. The first
		// attempted record then needs only its own file sync.
		if err := j.prepareEmptyAckLog(segmentID); err != nil {
			return err
		}
		state.Committed = true
		state.AckLog = true
		state.AckLogSealed = true
		// The cursor is in this same directory. Its final directory sync
		// seals both renames; a crash before then is recovered from the
		// already durable immutable segment and the old cursor.
		if err := atomicJSONBeforeDirectoryBarrier(j.path(segmentID, ".state"), stateWithoutEvents(state)); err != nil {
			return err
		}
	}
	cursor.FileID, cursor.Offset, cursor.LastSegmentID, cursor.Generation = segment.FileID, segment.EndOffset, segmentID, segment.SourceGeneration
	if segment.SourceBackedRaw {
		if segment.RawTailBytes <= 0 || segment.RawTailBytes > SourceTailProofBytes || len(segment.RawTailSHA256) != 64 {
			return ErrContentConflict
		}
		cursor.TailBytes, cursor.TailSHA256 = segment.RawTailBytes, segment.RawTailSHA256
	} else if len(segment.Raw) > 0 {
		tail := segment.Raw
		if len(tail) > SourceTailProofBytes {
			tail = tail[len(tail)-SourceTailProofBytes:]
		}
		sum := sha256.Sum256(tail)
		cursor.TailBytes, cursor.TailSHA256 = len(tail), hex.EncodeToString(sum[:])
	} else {
		cursor.TailBytes, cursor.TailSHA256 = 0, ""
	}
	if state.ProcessingReady && !state.Committed {
		// Sink lanes use only the prepared state and acknowledgement log. Do not
		// hold their segment lock through the slower cursor fsync.
		unlock(segmentLock)
		segmentLock = nil
		if err := atomicJSON(j.sourcePath(source, path), cursor); err != nil {
			return err
		}
		return j.finishPreparedSource(segmentID, false)
	}
	return atomicJSON(j.sourcePath(source, path), cursor)
}

func (j *Journal) finishPreparedSource(id string, allowRetired bool) error {
	lock, err := j.lockSegment(id)
	if err != nil {
		return err
	}
	defer unlock(lock)
	state, err := j.load(id)
	if errors.Is(err, os.ErrNotExist) {
		if allowRetired {
			return nil // a previously committed segment was already released
		}
		return ErrContentConflict
	}
	if err != nil {
		return err
	}
	if state.Released || state.Committed {
		return nil
	}
	if !state.ProcessingReady {
		return ErrContentConflict
	}
	state.ProcessingReady, state.Committed = false, true
	return atomicJSON(j.path(id, ".state"), stateWithoutEvents(state))
}

// RecoverSource finishes the source-cursor write for an immutable segment
// whose body and state reached disk before a crash. Older committed segments
// remain available to their independent consumers without moving the cursor
// backwards across a file rotation.
func (j *Journal) RecoverSource(source, path string) ([]string, error) {
	cursor, err := j.LoadSource(source, path)
	if err != nil {
		return nil, err
	}
	all, err := j.PendingSegments()
	if err != nil {
		return nil, err
	}
	pending := make([]string, 0)
	for _, id := range all {
		state, err := j.load(id)
		if err != nil {
			return nil, err
		}
		segment := state.Segment
		if segment.Source != source || segment.SourcePath != path {
			continue
		}
		if segment.Quarantined {
			return nil, fmt.Errorf("source %s at %s is quarantined: %w", source, path, ErrQuarantined)
		}
		if segment.Epoch != cursor.Epoch || segment.ParserVersion != cursor.ParserVersion || segment.KeyScheme != cursor.KeyScheme {
			return nil, ErrContentConflict
		}
		if cursor.LastSegmentID == id && state.ProcessingReady && !state.Committed {
			if err := j.CommitSource(source, path, id); err != nil {
				return nil, err
			}
		} else if segment.PreviousFileID == cursor.FileID && segment.PreviousOffset == cursor.Offset {
			if err := j.CommitSource(source, path, id); err != nil {
				return nil, err
			}
			cursor, err = j.LoadSource(source, path)
			if err != nil {
				return nil, err
			}
		} else if !state.Committed {
			return nil, fmt.Errorf("uncommitted stream segment has no matching source cursor: %w", ErrContentConflict)
		}
		pending = append(pending, id)
	}
	return pending, nil
}
