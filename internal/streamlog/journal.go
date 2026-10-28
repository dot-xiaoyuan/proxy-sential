// Package streamlog owns immutable, fsynced input segments and independent
// archive, search and projection acknowledgements. A failed database request
// remains "attempted" until its outcome has been reconciled.
package streamlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"proxy-sentinel/internal/normalized"
)

var (
	ErrContentConflict = errors.New("stream source position has different content")
	ErrUnconfirmed     = errors.New("stream segment has unconfirmed consumers")
	ErrSegmentTooLarge = errors.New("stream segment exceeds its durable bound")
	ErrQuarantined     = errors.New("stream segment is quarantined")
)

// The byte ceiling remains independent: a larger compact signal batch saves
// mechanical-disk journal syncs without allowing an oversized segment.
const MaxSegmentEvents = 1000
const MaxSegmentBytes = 4 << 20

type Lane string

const (
	Archive    Lane = "archive"
	Search     Lane = "search"
	Projection Lane = "projection"
	// RiskFeatures is checkpointed independently but scheduled by Search.
	RiskFeatures Lane = "risk_features"
)

type Status string

const (
	Pending       Status = "pending"
	Attempted     Status = "attempted"
	Acked         Status = "acked"
	NotApplicable Status = "not_applicable"
)

type Segment struct {
	Epoch                string             `json:"epoch"`
	Source               string             `json:"source"`
	SourcePath           string             `json:"source_path"`
	FileID               string             `json:"file_id"`
	PreviousFileID       string             `json:"previous_file_id"`
	PreviousOffset       int64              `json:"previous_offset"`
	StartOffset          int64              `json:"start_offset"`
	EndOffset            int64              `json:"end_offset"`
	ParserVersion        string             `json:"parser_version"`
	KeyScheme            string             `json:"key_scheme,omitempty"`
	PreviousGeneration   uint64             `json:"previous_generation,omitempty"`
	SourceGeneration     uint64             `json:"source_generation,omitempty"`
	EventOffsets         []int64            `json:"event_offsets,omitempty"`
	RawSHA256            string             `json:"raw_sha256,omitempty"`
	SourceBackedRaw      bool               `json:"source_backed_raw,omitempty"`
	RawIsStandardEvents  bool               `json:"raw_is_standard_events,omitempty"`
	EarlyProcessing      bool               `json:"early_processing,omitempty"`
	RawTailBytes         int                `json:"raw_tail_bytes,omitempty"`
	RawTailSHA256        string             `json:"raw_tail_sha256,omitempty"`
	ArchiveMonth         string             `json:"archive_month"`
	AcceptedAt           time.Time          `json:"accepted_at"`
	NeedsProjection      bool               `json:"needs_projection"`
	RiskFeaturesRequired bool               `json:"risk_features_required,omitempty"`
	SplitRiskFeatures    bool               `json:"split_risk_features,omitempty"`
	Quarantined          bool               `json:"quarantined,omitempty"`
	QuarantineReason     string             `json:"quarantine_reason,omitempty"`
	Raw                  []byte             `json:"raw,omitempty"`
	Events               []normalized.Event `json:"events"`
}

type State struct {
	ID              string          `json:"id"`
	ContentSHA256   string          `json:"content_sha256"`
	Segment         Segment         `json:"segment"`
	Acks            map[Lane]Status `json:"acks"`
	AckLog          bool            `json:"ack_log,omitempty"`
	AckLogSealed    bool            `json:"ack_log_sealed,omitempty"`
	ProcessingReady bool            `json:"processing_ready,omitempty"`
	Committed       bool            `json:"committed"`
	Released        bool            `json:"released"`
}

type Journal struct {
	dir        string
	resolveRaw func(Segment) ([]byte, error)
}

func (j *Journal) Directory() string { return j.dir }

// SetRawResolver enables source-file-backed segments. The resolver must prove
// the exact byte range and hash before any sink can consume it. Call before
// RecoverSource; existing inline segments remain self-contained.
func (j *Journal) SetRawResolver(resolve func(Segment) ([]byte, error)) {
	j.resolveRaw = resolve
}

func (j *Journal) HasRawResolver() bool { return j.resolveRaw != nil }

func Open(dir string) (*Journal, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("stream journal directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Journal{dir: dir}, nil
}

func segmentID(s Segment) string {
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%d", s.Epoch, s.Source, s.SourcePath, s.FileID, s.StartOffset, s.EndOffset)
	if s.SourceGeneration != 0 {
		key += fmt.Sprintf("\x00generation:%d", s.SourceGeneration)
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func contentHash(s Segment) (string, error) {
	encoded, err := json.Marshal(struct {
		SourcePath           string             `json:"source_path"`
		PreviousFileID       string             `json:"previous_file_id"`
		PreviousOffset       int64              `json:"previous_offset"`
		ParserVersion        string             `json:"parser_version"`
		KeyScheme            string             `json:"key_scheme,omitempty"`
		PreviousGeneration   uint64             `json:"previous_generation,omitempty"`
		SourceGeneration     uint64             `json:"source_generation,omitempty"`
		EventOffsets         []int64            `json:"event_offsets,omitempty"`
		RawSHA256            string             `json:"raw_sha256"`
		SourceBackedRaw      bool               `json:"source_backed_raw,omitempty"`
		RawIsStandardEvents  bool               `json:"raw_is_standard_events,omitempty"`
		EarlyProcessing      bool               `json:"early_processing,omitempty"`
		RawTailBytes         int                `json:"raw_tail_bytes,omitempty"`
		RawTailSHA256        string             `json:"raw_tail_sha256,omitempty"`
		Raw                  []byte             `json:"raw,omitempty"`
		NeedsProjection      bool               `json:"needs_projection"`
		RiskFeaturesRequired bool               `json:"risk_features_required,omitempty"`
		SplitRiskFeatures    bool               `json:"split_risk_features,omitempty"`
		Quarantined          bool               `json:"quarantined,omitempty"`
		QuarantineReason     string             `json:"quarantine_reason,omitempty"`
		Events               []normalized.Event `json:"events"`
	}{s.SourcePath, s.PreviousFileID, s.PreviousOffset, s.ParserVersion, s.KeyScheme, s.PreviousGeneration, s.SourceGeneration, s.EventOffsets, s.RawSHA256, s.SourceBackedRaw, s.RawIsStandardEvents, s.EarlyProcessing, s.RawTailBytes, s.RawTailSHA256, s.Raw, s.NeedsProjection, s.RiskFeaturesRequired, s.SplitRiskFeatures, s.Quarantined, s.QuarantineReason, s.Events})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func (j *Journal) Append(s Segment) (string, error) {
	return j.append(s, false)
}

func (j *Journal) append(s Segment, allowEarly bool) (string, error) {
	if s.Epoch == "" || s.Source == "" || s.SourcePath == "" || s.FileID == "" || s.ParserVersion == "" || s.EndOffset <= s.StartOffset || (len(s.Events) == 0 && s.NeedsProjection) {
		return "", errors.New("stream segment requires epoch, source, path, file, parser, positive offsets and projection events")
	}
	if (s.KeyScheme == "generation-v2" && (s.Source != "zeek-dhcp-binding" || s.ParserVersion != "zeek-dhcp-binding-v2" || s.PreviousGeneration == 0 || s.SourceGeneration < s.PreviousGeneration || s.SourceGeneration > s.PreviousGeneration+1)) ||
		(s.KeyScheme != "generation-v2" && (s.PreviousGeneration != 0 || s.SourceGeneration != 0)) {
		return "", ErrContentConflict
	}
	if s.Quarantined && (len(s.Raw) == 0 || len(s.Events) != 0 || s.NeedsProjection || s.RiskFeaturesRequired || s.QuarantineReason == "") {
		return "", errors.New("quarantined segment requires raw bytes, reason and no projected events")
	}
	if s.SplitRiskFeatures && (!s.RiskFeaturesRequired || len(s.Events) == 0) {
		return "", errors.New("split risk features require events and a risk-feature sink")
	}
	if s.RawIsStandardEvents && (s.Source != "device-signals" && s.Source != "shared-device-signals" || len(s.Raw) == 0 || len(s.Events) == 0 || s.SourceBackedRaw || s.Quarantined) {
		return "", errors.New("standard-event raw source requires inline device events")
	}
	if s.EarlyProcessing && (!allowEarly || (!s.RawIsStandardEvents && !s.SourceBackedRaw)) {
		return "", ErrContentConflict
	}
	if len(s.Raw) > 0 {
		rawHash := sha256.Sum256(s.Raw)
		if s.RawSHA256 != hex.EncodeToString(rawHash[:]) {
			return "", ErrContentConflict
		}
	}
	if s.SourceBackedRaw {
		if j.resolveRaw == nil || s.Source != "zeek-dhcp-binding" || len(s.Raw) == 0 ||
			int64(len(s.Raw)) != s.EndOffset-s.StartOffset || s.Quarantined {
			return "", ErrContentConflict
		}
		tail := s.Raw
		if len(tail) > SourceTailProofBytes {
			tail = tail[len(tail)-SourceTailProofBytes:]
		}
		sum := sha256.Sum256(tail)
		s.RawTailBytes, s.RawTailSHA256 = len(tail), hex.EncodeToString(sum[:])
		s.Raw = nil // Zeek's retained file is the recoverable source body.
	}
	if s.ArchiveMonth == "" {
		s.ArchiveMonth = time.Now().UTC().Format("200601")
	}
	if _, err := time.Parse("200601", s.ArchiveMonth); err != nil {
		return "", fmt.Errorf("invalid archive month: %w", err)
	}
	if s.AcceptedAt.IsZero() {
		s.AcceptedAt = time.Now().UTC()
	}
	if len(s.Events) > MaxSegmentEvents {
		return "", ErrSegmentTooLarge
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if len(encoded) > MaxSegmentBytes {
		return "", ErrSegmentTooLarge
	}
	id := segmentID(s)
	hash, err := contentHash(s)
	if err != nil {
		return "", err
	}
	lock, err := j.lockSegment(id)
	if err != nil {
		return "", err
	}
	defer unlock(lock)
	if old, err := j.load(id); err == nil {
		if old.ContentSHA256 != hash || old.Segment.ParserVersion != s.ParserVersion || old.Segment.RawSHA256 != s.RawSHA256 {
			return "", ErrContentConflict
		}
		// A previous directory sync may have failed after the body rename.
		// Reconfirm the immutable entry before offering it to a sink.
		if err := syncDir(j.dir); err != nil {
			return "", err
		}
		return id, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if s.EarlyProcessing {
		// The body rename's directory barrier also seals this empty log. Sink
		// attempts can then append records without another directory sync.
		if err := j.prepareEmptyAckLog(id); err != nil {
			return "", err
		}
	}
	if err := atomicJSON(j.path(id, ".segment"), s); err != nil {
		return "", err
	}
	// The immutable body is durable. CommitSource writes the first compact
	// state; the acknowledgement log is created with its first sink attempt.
	// A crash here reconstructs pending lanes from the body.
	return id, nil
}

func (j *Journal) Load(id string) (State, error) {
	state, err := j.load(id)
	if err != nil || state.Released || !state.Segment.SourceBackedRaw {
		return state, err
	}
	if j.resolveRaw == nil {
		return State{}, ErrContentConflict
	}
	raw, err := j.resolveRaw(state.Segment)
	if err != nil {
		return State{}, err
	}
	if int64(len(raw)) != state.Segment.EndOffset-state.Segment.StartOffset {
		return State{}, ErrContentConflict
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != state.Segment.RawSHA256 {
		return State{}, ErrContentConflict
	}
	state.Segment.Raw = raw
	return state, nil
}

func (j *Journal) load(id string) (State, error) {
	if !validID(id) {
		return State{}, errors.New("invalid segment id")
	}
	var state State
	data, err := os.ReadFile(j.path(id, ".state"))
	if errors.Is(err, os.ErrNotExist) {
		// A crash after the body rename but before the state rename leaves a
		// complete segment. Never silently advance it; reconstruct pending acks.
		body, bodyErr := os.ReadFile(j.path(id, ".segment"))
		if bodyErr != nil {
			return State{}, bodyErr
		}
		var segment Segment
		if bodyErr = json.Unmarshal(body, &segment); bodyErr != nil {
			return State{}, bodyErr
		}
		if segmentID(segment) != id {
			return State{}, ErrContentConflict
		}
		hash, bodyErr := contentHash(segment)
		if bodyErr != nil {
			return State{}, bodyErr
		}
		state = State{ID: id, ContentSHA256: hash, Segment: segment, ProcessingReady: segment.EarlyProcessing, Committed: segment.SourceBackedRaw && !segment.EarlyProcessing, Acks: map[Lane]Status{Archive: Pending, Search: Pending, Projection: Pending}}
		if segment.SplitRiskFeatures {
			state.Acks[RiskFeatures] = Pending
		}
		if len(segment.Events) == 0 {
			state.Acks[Archive], state.Acks[Search] = NotApplicable, NotApplicable
		}
		if !segment.NeedsProjection {
			state.Acks[Projection] = NotApplicable
		}
		if _, ackErr := os.Stat(j.path(id, ".acklog")); ackErr == nil {
			state.AckLog = true
			state.AckLogSealed = segment.EarlyProcessing
		} else if !errors.Is(ackErr, os.ErrNotExist) {
			return State{}, ackErr
		}
		if state.AckLog {
			if _, err := j.applyAckLog(id, &state); err != nil {
				return State{}, err
			}
		}
		return state, nil
	}
	if err != nil {
		return State{}, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	if state.ID != id {
		return State{}, ErrContentConflict
	}
	if state.Released {
		return state, nil
	}
	data, err = os.ReadFile(j.path(id, ".segment"))
	if err != nil {
		return State{}, err
	}
	var segment Segment
	if err := json.Unmarshal(data, &segment); err != nil {
		return State{}, err
	}
	hash, err := contentHash(segment)
	if err != nil {
		return State{}, err
	}
	if hash != state.ContentSHA256 || segmentID(segment) != id {
		return State{}, ErrContentConflict
	}
	state.Segment = segment
	if state.AckLog {
		if _, err := os.Stat(j.path(id, ".acklog")); err == nil {
			if _, err := j.applyAckLog(id, &state); err != nil {
				return State{}, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return State{}, err
		}
	}
	return state, nil
}

// PendingSegments is an on-startup recovery scan. It includes a complete body
// whose state rename was interrupted, so no acknowledged source bytes vanish.
func (j *Journal) PendingSegments() ([]string, error) {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, err
	}
	ids := make(map[string]struct{})
	for _, entry := range entries {
		name := entry.Name()
		for _, suffix := range []string{".state", ".segment"} {
			if strings.HasSuffix(name, suffix) {
				id := strings.TrimSuffix(name, suffix)
				if validID(id) {
					ids[id] = struct{}{}
				}
			}
		}
	}
	type pending struct {
		id         string
		acceptedAt time.Time
	}
	items := make([]pending, 0, len(ids))
	for id := range ids {
		state, err := j.load(id)
		if err != nil {
			return nil, fmt.Errorf("recover stream segment %s: %w", id, err)
		}
		if state.Released {
			if err := j.retire(id); err != nil {
				return nil, err
			}
			continue
		}
		items = append(items, pending{id: id, acceptedAt: state.Segment.AcceptedAt})
	}
	sort.Slice(items, func(i, k int) bool {
		if items[i].acceptedAt.Equal(items[k].acceptedAt) {
			return items[i].id < items[k].id
		}
		return items[i].acceptedAt.Before(items[k].acceptedAt)
	})
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.id)
	}
	return result, nil
}

// PendingLanes returns only unfinished sink work. In particular, a lane marked
// not applicable must never enter a worker queue: finalization may retire its
// segment before that worker reads the queued ID.
func (j *Journal) PendingLanes(id string) ([]Lane, error) {
	state, err := j.load(id)
	if err != nil {
		return nil, err
	}
	if state.Released {
		return nil, nil
	}
	lanes := make([]Lane, 0, 3)
	for _, lane := range []Lane{Archive, Projection, Search} {
		switch state.Acks[lane] {
		case Pending, Attempted:
			lanes = append(lanes, lane)
		case Acked, NotApplicable:
		default:
			return nil, fmt.Errorf("stream segment %s has invalid %s lane status %q: %w", id, lane, state.Acks[lane], ErrContentConflict)
		}
	}
	// The existing bounded search worker also owns the feature substep. After
	// a restart, an acknowledged search must still enqueue pending features.
	if state.Segment.SplitRiskFeatures {
		switch state.Acks[RiskFeatures] {
		case Pending, Attempted:
			if state.Acks[Search] == Acked {
				lanes = append(lanes, Search)
			}
		case Acked:
		default:
			return nil, fmt.Errorf("stream segment %s has invalid risk feature status: %w", id, ErrContentConflict)
		}
	}
	return lanes, nil
}

func requiredLanes(segment Segment) []Lane {
	if segment.SplitRiskFeatures {
		return []Lane{Archive, Search, Projection, RiskFeatures}
	}
	return []Lane{Archive, Search, Projection}
}

func validLane(lane Lane) bool {
	return lane == Archive || lane == Search || lane == Projection || lane == RiskFeatures
}

func (j *Journal) BeginAttempt(id string, lane Lane) error { return j.setAck(id, lane, Attempted) }
func (j *Journal) Ack(id string, lane Lane) error          { return j.setAck(id, lane, Acked) }

// AbortUnsentAttempt is valid only when the caller has not invoked the sink.
// A slow local fsync can exhaust the request context after BeginAttempt; in
// that case an attempted marker must not strand a write that never began.
func (j *Journal) AbortUnsentAttempt(id string, lane Lane) error {
	if !validLane(lane) {
		return errors.New("invalid stream lane")
	}
	lock, err := j.lockSegment(id)
	if err != nil {
		return err
	}
	defer unlock(lock)
	state, err := j.load(id)
	if err != nil {
		return err
	}
	if state.Released || state.Acks[lane] == Acked {
		return ErrContentConflict
	}
	if state.Acks[lane] == Pending {
		return nil
	}
	if state.Acks[lane] != Attempted {
		return ErrContentConflict
	}
	if state.AckLog {
		return j.appendAck(id, lane, Pending, state.AckLogSealed)
	}
	state.Acks[lane] = Pending
	return atomicJSON(j.path(id, ".state"), stateWithoutEvents(state))
}

func (j *Journal) setAck(id string, lane Lane, status Status) error {
	if !validLane(lane) {
		return errors.New("invalid stream lane")
	}
	lock, err := j.lockSegment(id)
	if err != nil {
		return err
	}
	defer unlock(lock)
	state, err := j.load(id)
	if err != nil {
		return err
	}
	if state.Released || state.Acks[lane] == NotApplicable || state.Acks[lane] == "" {
		return errors.New("stream lane is not pending")
	}
	if !state.Committed && !state.ProcessingReady {
		return ErrUnconfirmed
	}
	if state.Acks[lane] == Acked {
		return nil
	}
	if state.AckLog {
		if _, err := os.Stat(j.path(id, ".acklog")); errors.Is(err, os.ErrNotExist) {
			return j.createAckLogWithRecord(id, lane, status)
		} else if err != nil {
			return err
		}
		return j.appendAck(id, lane, status, state.AckLogSealed)
	}
	if state.Segment.SourceBackedRaw || state.Segment.EarlyProcessing {
		return j.createAckLogWithRecord(id, lane, status)
	}
	state.Acks[lane] = status
	return atomicJSON(j.path(id, ".state"), stateWithoutEvents(state))
}

func (j *Journal) Release(id string) error {
	lock, err := j.lockSegment(id)
	if err != nil {
		return err
	}
	defer unlock(lock)
	state, err := j.load(id)
	if err != nil {
		return err
	}
	if state.Released {
		return j.retire(id)
	}
	if state.Segment.Quarantined {
		return ErrQuarantined
	}
	if !state.Committed {
		return ErrUnconfirmed
	}
	for _, lane := range requiredLanes(state.Segment) {
		if status := state.Acks[lane]; status != Acked && status != NotApplicable {
			return ErrUnconfirmed
		}
	}
	state.Released = true
	if err := atomicJSON(j.path(id, ".state"), stateWithoutEvents(state)); err != nil {
		return err
	}
	return j.retire(id)
}

// retire persists removal of the large body before removing its compact
// completion marker. A crash at either unlink is recoverable on the next scan.
func (j *Journal) retire(id string) error {
	if err := os.Remove(j.path(id, ".segment")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDir(j.dir); err != nil {
		return err
	}
	if err := os.Remove(j.path(id, ".acklog")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(j.path(id, ".state")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(j.dir)
}

func stateWithoutEvents(state State) State {
	state.Segment.Events = nil
	state.Segment.Raw = nil
	return state
}

func (j *Journal) path(id, suffix string) string { return filepath.Join(j.dir, id+suffix) }
func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// Different segments must not wait for another segment's fsync. The fixed
// stripes bound lock-file growth while preserving cross-process state updates.
func (j *Journal) lockSegment(id string) (*os.File, error) {
	if !validID(id) {
		return nil, errors.New("invalid segment id")
	}
	return j.lockFile(".segment-lock-" + id[:2])
}

func (j *Journal) lockFile(name string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(j.dir, name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }

func atomicJSON(path string, value any) error {
	if err := atomicJSONBeforeDirectoryBarrier(path, value); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// The caller must sync this directory before treating the rename as durable.
// CommitSource uses the cursor's subsequent atomicJSON for that barrier.
func atomicJSONBeforeDirectoryBarrier(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".stream-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	return nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
