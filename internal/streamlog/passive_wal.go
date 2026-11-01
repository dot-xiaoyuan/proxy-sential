package streamlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/streamwal"
)

var (
	ErrPassiveWALWritesDisabled = errors.New("passive WAL is active; new WAL capture is disabled, legacy writes are forbidden")
	ErrPassiveWALStopped        = errors.New("passive WAL stopped; reopen and reconcile before continuing")
)

type PassiveWALOptions struct {
	WriteEnabled  bool
	QuarantineDir string
	MaxSegments   int // Includes finalized records until checkpoint/retirement exists.
	WAL           streamwal.Options
	// BeforeRecovery validates the existing fixed source start while its lease
	// is held, before any source recovery or WAL genesis can change disk state.
	// Worker integrations must supply this gate; isolated library tests may omit it.
	BeforeRecovery func(SourceCursor) error
}

type PassiveWALReference struct {
	WALDirectory  string `json:"wal_directory"`
	LSN           uint64 `json:"lsn"`
	Offset        int64  `json:"offset"`
	Length        int    `json:"length"`
	ContentSHA256 string `json:"content_sha256"`
}

type passiveWALEntry struct {
	state   State // Compact metadata only; body exists once in its accept frame.
	receipt streamwal.Receipt
	lanes   [3]sync.Mutex
	finish  sync.Mutex
}

type passiveTransition struct {
	ContentSHA256 string `json:"content_sha256"`
	Lane          Lane   `json:"lane,omitempty"`
	Status        Status `json:"status,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// PassiveWALJournal is experimental: it has no rotation/checkpoint/GC and must
// not be enabled for sustained capture. It owns the legacy source lease. Its
// legacy cursor is the immutable cutover anchor once the genesis frame exists.
type PassiveWALJournal struct {
	legacy       *Journal
	wal          *streamwal.Log
	dir, path    string
	opts         PassiveWALOptions
	releaseLease func()
	mu           sync.Mutex
	cursor       SourceCursor
	genesis      bool
	entries      map[string]*passiveWALEntry
	legacyIDs    map[string]struct{}
	terminal     error
	quarantined  bool
	closed       bool
	sourceMu     sync.Mutex
	closeOnce    sync.Once
	closeErr     error
}

var _ ProcessorJournal = (*PassiveWALJournal)(nil)
var _ ProcessorJournal = (*Journal)(nil)

// AppendAndCommitPassive retains the v1 durable sequence for the capture seam.
// An append ID is returned even if source commit fails, preserving recovery.
func (j *Journal) AppendAndCommitPassive(segment Segment) (string, error) {
	if segment.Source != "passive-discovery" {
		return "", ErrContentConflict
	}
	id, err := j.Append(segment)
	if err != nil {
		return id, err
	}
	return id, j.CommitSource(segment.Source, segment.SourcePath, id)
}

// OpenPassiveWALJournal acquires the source lease itself; callers must not hold
// another lease for this source. With no WAL and WriteEnabled=false it delegates
// to v1 and leaves recovery to the caller. BeforeRecovery runs against the
// original cursor, under the lease, before either recovery or genesis creation.
// An existing WAL is always replayed, but new capture remains prohibited while
// WriteEnabled=false. Lane completion and quarantine remain available.
func OpenPassiveWALJournal(legacy *Journal, path string, opts PassiveWALOptions) (*PassiveWALJournal, error) {
	if legacy == nil || path == "" {
		return nil, errors.New("passive WAL requires legacy journal and source path")
	}
	if opts.MaxSegments == 0 {
		opts.MaxSegments = 4096
	}
	if opts.MaxSegments < 1 || opts.MaxSegments > 8192 {
		return nil, streamwal.ErrBounds
	}
	release, err := legacy.AcquireSourceLease("passive-discovery", path)
	if err != nil {
		return nil, err
	}
	j := &PassiveWALJournal{legacy: legacy, path: path, opts: opts, dir: filepath.Join(legacy.Directory(), "passive-wal-v1"), releaseLease: release, entries: map[string]*passiveWALEntry{}, legacyIDs: map[string]struct{}{}}
	fail := func(err error) (*PassiveWALJournal, error) {
		if j.wal != nil {
			_ = j.wal.Close()
		}
		release()
		return nil, err
	}
	j.cursor, err = legacy.LoadSource("passive-discovery", path)
	if err != nil {
		return fail(err)
	}
	if opts.BeforeRecovery != nil {
		if err := opts.BeforeRecovery(j.cursor); err != nil {
			return fail(err)
		}
	}
	_, statErr := os.Stat(j.dir)
	if errors.Is(statErr, os.ErrNotExist) && !opts.WriteEnabled {
		return j, nil
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fail(statErr)
	}
	// Preserve the old worker's per-pending-ID manifest gate in pure v1 mode.
	// WAL activation/recovery additionally refuses any unresolved manifest.
	if err := checkPassiveQuarantine(opts.QuarantineDir); err != nil {
		return fail(err)
	}
	if j.cursor.ParserVersion != "passive-frame-v1" || j.cursor.KeyScheme != "" || j.cursor.Generation != 0 {
		return fail(ErrContentConflict)
	}
	ids, err := legacy.RecoverSource("passive-discovery", path)
	if err != nil {
		return fail(err)
	}
	if len(ids) > opts.MaxSegments {
		return fail(streamwal.ErrCapacity)
	}
	for _, id := range ids {
		j.legacyIDs[id] = struct{}{}
	}
	// A previously appended v1 body may have completed its source commit during
	// recovery. That verified position is the new WAL's immutable cutover anchor.
	j.cursor, err = legacy.LoadSource("passive-discovery", path)
	if err != nil {
		return fail(err)
	}
	j.wal, err = streamwal.Open(j.dir, opts.WAL)
	if err != nil {
		return fail(err)
	}
	if err := j.wal.Replay(j.replay); err != nil {
		return fail(err)
	}
	if !j.genesis {
		if !opts.WriteEnabled {
			return fail(ErrPassiveWALWritesDisabled)
		}
		payload, _ := json.Marshal(j.cursor)
		if _, err := j.persist("genesis", sourceCursorID("passive-discovery", path), payload); err != nil {
			return fail(err)
		}
		j.genesis = true
	}
	if opts.WriteEnabled && j.quarantined {
		return fail(ErrQuarantined)
	}
	return j, nil
}

func checkPassiveQuarantine(dir string) error {
	if dir == "" {
		return nil
	}
	f, err := os.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	names, err := f.Readdirnames(8193)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(names) > 8192 {
		return streamwal.ErrCapacity
	}
	for _, name := range names {
		if strings.HasSuffix(name, ".json") {
			return fmt.Errorf("unresolved passive quarantine manifest %s: %w", name, ErrQuarantined)
		}
	}
	return nil
}

func (j *PassiveWALJournal) persist(kind, id string, payload []byte) (streamwal.Receipt, error) {
	j.mu.Lock()
	terminal, closed := j.terminal, j.closed
	j.mu.Unlock()
	if terminal != nil {
		return streamwal.Receipt{}, terminal
	}
	if closed {
		return streamwal.Receipt{}, ErrPassiveWALStopped
	}
	class := streamwal.Control
	if kind == "accept" {
		class = streamwal.Data
	}
	future, err := j.wal.AppendWithClass(context.Background(), streamwal.Record{Kind: kind, ID: id, Payload: payload}, class)
	if err != nil {
		if errors.Is(err, streamwal.ErrStopped) {
			return streamwal.Receipt{}, j.halt(err)
		}
		return streamwal.Receipt{}, err
	}
	result := <-future
	if result.Err != nil {
		return streamwal.Receipt{}, j.halt(result.Err)
	}
	return result.Receipt, nil
}

func (j *PassiveWALJournal) halt(err error) error {
	if errors.Is(err, streamwal.ErrCorrupt) || errors.Is(err, streamwal.ErrTail) {
		err = errors.Join(ErrContentConflict, err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.terminal == nil {
		j.terminal = errors.Join(ErrPassiveWALStopped, err)
	}
	return j.terminal
}

func validatePassiveWALSegment(s Segment) error {
	if s.Source != "passive-discovery" || s.SourcePath == "" || s.FileID == "" || s.Epoch == "" || s.ParserVersion != "passive-frame-v1" ||
		s.KeyScheme != "" || s.SourceGeneration != 0 || s.PreviousGeneration != 0 || s.SourceBackedRaw || s.RawIsStandardEvents || s.EarlyProcessing ||
		s.Quarantined || s.QuarantineReason != "" || s.RiskFeaturesRequired || s.SplitRiskFeatures || len(s.Raw) != 0 || s.RawSHA256 != "" || s.RawTailBytes != 0 || s.RawTailSHA256 != "" || len(s.EventOffsets) != 0 ||
		!s.NeedsProjection || s.AcceptedAt.IsZero() || len(s.Events) < 1 || len(s.Events) > MaxSegmentEvents {
		return ErrContentConflict
	}
	if _, err := time.Parse("200601", s.ArchiveMonth); err != nil {
		return ErrContentConflict
	}
	for _, event := range s.Events {
		scope, _ := event.Observer["capture_scope_id"].(string)
		issue, _ := event.Observer["capture_scope_issue"].(string)
		if event.Type != "discovery" || event.EventID == "" || scope == "" || issue != "" {
			return ErrContentConflict
		}
		if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
			return ErrContentConflict
		}
	}
	return nil
}

func (j *PassiveWALJournal) AppendAndCommitPassive(s Segment) (string, error) {
	j.sourceMu.Lock()
	defer j.sourceMu.Unlock()
	j.mu.Lock()
	terminal, closed := j.terminal, j.closed
	j.mu.Unlock()
	if terminal != nil {
		return "", terminal
	}
	if closed {
		return "", ErrPassiveWALStopped
	}
	if j.wal == nil {
		return j.legacy.AppendAndCommitPassive(s)
	}
	if !j.opts.WriteEnabled {
		return "", ErrPassiveWALWritesDisabled
	}
	if err := validatePassiveWALSegment(s); err != nil {
		return "", err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if len(raw) > MaxSegmentBytes {
		return "", ErrSegmentTooLarge
	}
	// Reload the encoded body once so caller-owned maps cannot change the state
	// being validated or the proof used to compare this immutable accept.
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(raw, canonical) {
		return "", ErrContentConflict
	}
	hash, err := contentHash(s)
	if err != nil {
		return "", err
	}
	id := segmentID(s)
	j.mu.Lock()
	entry := j.entries[id]
	cursor := j.cursor
	count := len(j.entries)
	quarantined := j.quarantined
	if quarantined {
		j.mu.Unlock()
		return "", ErrQuarantined
	}
	if entry != nil {
		prior := entry.state.ContentSHA256
		j.mu.Unlock()
		if prior != hash {
			return "", ErrContentConflict
		}
		return id, nil
	}
	j.mu.Unlock()
	if count >= j.opts.MaxSegments {
		return "", streamwal.ErrCapacity
	}
	if err := validateSourceSegment(cursor, s, "passive-discovery", j.path); err != nil {
		return "", err
	}
	receipt, err := j.persist("accept", id, raw)
	if err != nil {
		return id, err
	}
	j.mu.Lock()
	j.applyAccept(id, s, hash, receipt)
	j.mu.Unlock()
	return id, nil
}

func (j *PassiveWALJournal) applyAccept(id string, s Segment, hash string, receipt streamwal.Receipt) {
	j.entries[id] = &passiveWALEntry{state: stateWithoutEvents(State{ID: id, ContentSHA256: hash, Segment: s, Committed: true, Acks: map[Lane]Status{Archive: Pending, Search: Pending, Projection: Pending}}), receipt: receipt}
	j.cursor.FileID = s.FileID
	j.cursor.Offset = s.EndOffset
	j.cursor.LastSegmentID = id
	j.cursor.TailBytes = 0
	j.cursor.TailSHA256 = ""
}

func (j *PassiveWALJournal) replay(record streamwal.Entry) error {
	r := record.Record
	if r.Kind == "genesis" {
		if j.genesis || record.Receipt.LSN != 1 || r.ID != sourceCursorID("passive-discovery", j.path) {
			return ErrContentConflict
		}
		var cursor SourceCursor
		if err := json.Unmarshal(r.Payload, &cursor); err != nil {
			return err
		}
		old, _ := json.Marshal(j.cursor)
		next, _ := json.Marshal(cursor)
		if !bytes.Equal(old, next) {
			return fmt.Errorf("legacy cursor changed after WAL cutover: %w", ErrContentConflict)
		}
		j.genesis = true
		return nil
	}
	if !j.genesis {
		return ErrContentConflict
	}
	if r.Kind == "accept" {
		if j.quarantined {
			return ErrContentConflict
		}
		if len(j.entries) >= j.opts.MaxSegments {
			return streamwal.ErrCapacity
		}
		var s Segment
		if err := json.Unmarshal(r.Payload, &s); err != nil {
			return err
		}
		if err := validatePassiveWALSegment(s); err != nil {
			return err
		}
		if segmentID(s) != r.ID || j.entries[r.ID] != nil {
			return ErrContentConflict
		}
		if err := validateSourceSegment(j.cursor, s, "passive-discovery", j.path); err != nil {
			return err
		}
		hash, err := contentHash(s)
		if err != nil {
			return err
		}
		j.applyAccept(r.ID, s, hash, record.Receipt)
		return nil
	}
	entry := j.entries[r.ID]
	if entry == nil {
		return ErrContentConflict
	}
	var transition passiveTransition
	if err := json.Unmarshal(r.Payload, &transition); err != nil {
		return err
	}
	if err := applyPassiveTransition(&entry.state, r.Kind, transition); err != nil {
		return err
	}
	if r.Kind == "quarantine" {
		j.quarantined = true
	}
	return nil
}

func applyPassiveTransition(state *State, kind string, t passiveTransition) error {
	if t.ContentSHA256 != state.ContentSHA256 || state.Released || state.Segment.Quarantined {
		return ErrContentConflict
	}
	switch kind {
	case "lane":
		if passiveLaneIndex(t.Lane) < 0 {
			return ErrContentConflict
		}
		previous := state.Acks[t.Lane]
		if previous == Pending && t.Status != Attempted || previous == Attempted && t.Status != Acked && t.Status != Pending || previous == Acked {
			return ErrContentConflict
		}
		state.Acks[t.Lane] = t.Status
	case "finalized":
		for _, lane := range []Lane{Archive, Search, Projection} {
			if state.Acks[lane] != Acked {
				return ErrUnconfirmed
			}
		}
		state.Released = true
	case "quarantine":
		if t.Reason == "" || len(t.Reason) > 512 {
			return ErrContentConflict
		}
		state.Segment.Quarantined = true
		state.Segment.QuarantineReason = t.Reason
	default:
		return ErrContentConflict
	}
	return nil
}

func passiveLaneIndex(lane Lane) int {
	switch lane {
	case Archive:
		return 0
	case Search:
		return 1
	case Projection:
		return 2
	}
	return -1
}

func clonePassiveState(state State) State {
	copy := state
	copy.Acks = make(map[Lane]Status, len(state.Acks))
	for lane, status := range state.Acks {
		copy.Acks[lane] = status
	}
	return copy
}

func (j *PassiveWALJournal) entry(id string) (*passiveWALEntry, State, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, State{}, ErrPassiveWALStopped
	}
	if j.terminal != nil {
		return nil, State{}, j.terminal
	}
	entry := j.entries[id]
	if entry == nil {
		return nil, State{}, nil
	}
	return entry, clonePassiveState(entry.state), nil
}

func (j *PassiveWALJournal) Load(id string) (State, error) { return j.load(id) }
func (j *PassiveWALJournal) load(id string) (State, error) {
	entry, state, err := j.entry(id)
	if err != nil {
		return State{}, err
	}
	if entry == nil {
		return j.legacy.Load(id)
	}
	raw, err := j.wal.Read(entry.receipt)
	if err != nil {
		return State{}, j.halt(err)
	}
	if raw.Kind != "accept" || raw.ID != id {
		return State{}, j.halt(ErrContentConflict)
	}
	var body Segment
	if err := json.Unmarshal(raw.Payload, &body); err != nil {
		return State{}, j.halt(errors.Join(ErrContentConflict, err))
	}
	hash, err := contentHash(body)
	if err != nil {
		return State{}, err
	}
	if hash != state.ContentSHA256 || segmentID(body) != id {
		return State{}, j.halt(ErrContentConflict)
	}
	if state.Segment.Quarantined {
		body.Quarantined = true
		body.QuarantineReason = state.Segment.QuarantineReason
	}
	state.Segment = body
	return state, nil
}

func (j *PassiveWALJournal) loadPendingStatus(id string) (State, error) {
	entry, state, err := j.entry(id)
	if err != nil {
		return State{}, err
	}
	if entry == nil {
		return j.legacy.loadPendingStatus(id)
	}
	return state, nil
}

func (j *PassiveWALJournal) LoadSource(source, path string) (SourceCursor, error) {
	if source != "passive-discovery" || path != j.path {
		return SourceCursor{}, ErrContentConflict
	}
	if j.wal == nil {
		return j.legacy.LoadSource(source, path)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.terminal != nil {
		return SourceCursor{}, j.terminal
	}
	return j.cursor, nil
}

func (j *PassiveWALJournal) RecoverSource(source, path string) ([]string, error) {
	if source != "passive-discovery" || path != j.path {
		return nil, ErrContentConflict
	}
	if j.wal == nil {
		return j.legacy.RecoverSource(source, path)
	}
	j.mu.Lock()
	ids := make([]string, 0, len(j.entries)+len(j.legacyIDs))
	for id := range j.legacyIDs {
		ids = append(ids, id)
	}
	for id, entry := range j.entries {
		if !entry.state.Released {
			ids = append(ids, id)
		}
	}
	j.mu.Unlock()
	type item struct {
		id string
		at time.Time
	}
	items := make([]item, 0, len(ids))
	for _, id := range ids {
		// Startup recovery verifies the retained body as well as metadata. A
		// surviving .state file is not proof that legacy evidence still exists.
		state, err := j.load(id)
		if errors.Is(err, os.ErrNotExist) {
			j.mu.Lock()
			_, legacyPending := j.legacyIDs[id]
			_, walPending := j.entries[id]
			j.mu.Unlock()
			if !legacyPending && !walPending {
				continue // A concurrent, successful legacy Release removed it.
			}
			return nil, fmt.Errorf("pending segment %s disappeared: %w", id, err)
		}
		if err != nil {
			return nil, err
		}
		if state.Segment.Quarantined {
			return nil, ErrQuarantined
		}
		if !state.Released {
			items = append(items, item{id, state.Segment.AcceptedAt})
		}
	}
	sort.Slice(items, func(a, b int) bool {
		if items[a].at.Equal(items[b].at) {
			return items[a].id < items[b].id
		}
		return items[a].at.Before(items[b].at)
	})
	ids = ids[:0]
	for _, item := range items {
		ids = append(ids, item.id)
	}
	return ids, nil
}

func (j *PassiveWALJournal) PendingLanes(id string) ([]Lane, error) {
	entry, _, err := j.entry(id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return j.legacy.PendingLanes(id)
	}
	state, err := j.loadPendingStatus(id)
	if err != nil {
		return nil, err
	}
	if state.Released {
		return nil, nil
	}
	if state.Segment.Quarantined {
		return nil, ErrQuarantined
	}
	var lanes []Lane
	for _, lane := range []Lane{Archive, Projection, Search} {
		if state.Acks[lane] != Acked {
			lanes = append(lanes, lane)
		}
	}
	return lanes, nil
}

func (j *PassiveWALJournal) setAckWithProof(id string, lane Lane, status Status, proof string) error {
	entry, _, err := j.entry(id)
	if err != nil {
		return err
	}
	if entry == nil {
		return j.legacy.setAckWithProof(id, lane, status, proof)
	}
	index := passiveLaneIndex(lane)
	if index < 0 {
		return ErrContentConflict
	}
	entry.lanes[index].Lock()
	defer entry.lanes[index].Unlock()
	_, state, err := j.entry(id)
	if err != nil {
		return err
	}
	if proof == "" {
		state, err = j.load(id)
		if err != nil {
			return err
		}
	} else if proof != state.ContentSHA256 {
		return ErrContentConflict
	}
	if state.Released || state.Segment.Quarantined {
		return ErrContentConflict
	}
	if state.Acks[lane] == Acked && status == Pending {
		return ErrContentConflict
	}
	if state.Acks[lane] == Acked || state.Acks[lane] == status {
		return nil
	}
	t := passiveTransition{ContentSHA256: state.ContentSHA256, Lane: lane, Status: status}
	if err := applyPassiveTransition(&state, "lane", t); err != nil {
		return err
	}
	raw, _ := json.Marshal(t)
	if _, err := j.persist("lane", id, raw); err != nil {
		return err
	}
	j.mu.Lock()
	err = applyPassiveTransition(&entry.state, "lane", t)
	j.mu.Unlock()
	return err
}

func (j *PassiveWALJournal) BeginAttempt(id string, lane Lane) error {
	return j.setAckWithProof(id, lane, Attempted, "")
}
func (j *PassiveWALJournal) Ack(id string, lane Lane) error {
	return j.setAckWithProof(id, lane, Acked, "")
}
func (j *PassiveWALJournal) AbortUnsentAttempt(id string, lane Lane) error {
	entry, _, err := j.entry(id)
	if err != nil {
		return err
	}
	if entry == nil {
		return j.legacy.AbortUnsentAttempt(id, lane)
	}
	return j.setAckWithProof(id, lane, Pending, "")
}

func (j *PassiveWALJournal) Release(id string) error {
	entry, _, err := j.entry(id)
	if err != nil {
		return err
	}
	if entry == nil {
		if err := j.legacy.Release(id); err != nil {
			return err
		}
		j.mu.Lock()
		delete(j.legacyIDs, id)
		j.mu.Unlock()
		return nil
	}
	entry.finish.Lock()
	defer entry.finish.Unlock()
	for i := range entry.lanes {
		entry.lanes[i].Lock()
		defer entry.lanes[i].Unlock()
	}
	state, err := j.load(id)
	if err != nil {
		return err
	}
	if state.Released {
		return nil
	}
	if state.Segment.Quarantined {
		return ErrQuarantined
	}
	t := passiveTransition{ContentSHA256: state.ContentSHA256}
	if err := applyPassiveTransition(&state, "finalized", t); err != nil {
		return err
	}
	raw, _ := json.Marshal(t)
	if _, err := j.persist("finalized", id, raw); err != nil {
		return err
	}
	j.mu.Lock()
	err = applyPassiveTransition(&entry.state, "finalized", t)
	j.mu.Unlock()
	return err
}

// Quarantine records a durable failed scope/body reference without copying the
// body into a fabricated v1 segment. New capture and release then fail closed.
func (j *PassiveWALJournal) Quarantine(id, reason string) error {
	// Serialize the source gate with accept validation and commit. Once this
	// record is durable, no later accept can pass a stale quarantine check.
	j.sourceMu.Lock()
	defer j.sourceMu.Unlock()
	entry, _, err := j.entry(id)
	if err != nil {
		return err
	}
	if entry == nil {
		return errors.New("legacy quarantine requires its existing manifest workflow")
	}
	entry.finish.Lock()
	defer entry.finish.Unlock()
	for i := range entry.lanes {
		entry.lanes[i].Lock()
		defer entry.lanes[i].Unlock()
	}
	state, err := j.load(id)
	if err != nil {
		return err
	}
	if state.Segment.Quarantined {
		return nil
	}
	t := passiveTransition{ContentSHA256: state.ContentSHA256, Reason: reason}
	if err := applyPassiveTransition(&state, "quarantine", t); err != nil {
		return err
	}
	raw, _ := json.Marshal(t)
	if _, err := j.persist("quarantine", id, raw); err != nil {
		return err
	}
	j.mu.Lock()
	err = applyPassiveTransition(&entry.state, "quarantine", t)
	if err == nil {
		j.quarantined = true
	}
	j.mu.Unlock()
	return err
}

func (j *PassiveWALJournal) V2SegmentReference(id string) (PassiveWALReference, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	entry := j.entries[id]
	if entry == nil {
		return PassiveWALReference{}, false
	}
	r := entry.receipt
	return PassiveWALReference{WALDirectory: j.dir, LSN: r.LSN, Offset: r.Offset, Length: r.Length, ContentSHA256: entry.state.ContentSHA256}, true
}

func (j *PassiveWALJournal) Close() error {
	j.sourceMu.Lock()
	defer j.sourceMu.Unlock()
	j.closeOnce.Do(func() {
		j.mu.Lock()
		j.closed = true
		j.mu.Unlock()
		if j.wal != nil {
			j.closeErr = j.wal.Close()
		}
		j.releaseLease()
	})
	return j.closeErr
}
