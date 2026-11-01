package streamlog

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Writer exposes independently recoverable sinks. Reconcile methods run only
// after a write was attempted without a durable acknowledgement.
type Writer interface {
	WriteBody(context.Context, string, Segment) error
	ReconcileBody(context.Context, string, Segment) error
	WriteSearch(context.Context, string, Segment) error
	ReconcileSearch(context.Context, string, Segment) error
	Project(context.Context, string, Segment) error
	ReconcileProjection(context.Context, string, Segment) error
}

// UnsentLaneError is returned only when a writer can prove no sink request was
// dispatched during this attempt. A generic cancellation or timeout does not
// provide that proof and must retain the durable Attempted marker.
type UnsentLaneError struct{ Cause error }

func (e *UnsentLaneError) Error() string { return "stream lane not dispatched: " + e.Cause.Error() }
func (e *UnsentLaneError) Unwrap() error { return e.Cause }

// SegmentFinalizer persists cross-lane metadata after every required sink has
// acknowledged, while the recoverable segment still exists.
type SegmentFinalizer interface {
	FinalizeSegment(context.Context, string, Segment) error
}

// LanePreflight checks local, deterministic input before an attempted marker
// makes a sink write ambiguous. It must not contact an external sink.
type LanePreflight interface {
	Preflight(Lane, Segment) error
}

// RiskFeatureWriter separates two ClickHouse requests so a search timeout
// cannot strand a feature insert that has never been sent. Legacy segments
// retain their combined ambiguous acknowledgement and are never replayed.
type RiskFeatureWriter interface {
	WriteRiskFeatures(context.Context, string, Segment) error
	ReconcileRiskFeatures(context.Context, string, Segment) error
}

// ProcessorStage identifies a bounded operation; labels never contain segment IDs
// or user data. Journal stages include local lock/disk work; write, reconcile and
// finalize measure the sink call, including its own bounded input preparation.
type ProcessorStage string

const (
	StageLoad         ProcessorStage = "load"
	StagePreflight    ProcessorStage = "preflight"
	StageBeginAttempt ProcessorStage = "begin_attempt"
	StageWrite        ProcessorStage = "write"
	StageReconcile    ProcessorStage = "reconcile"
	StageAck          ProcessorStage = "ack"
	StageFinalize     ProcessorStage = "finalize"
	StageRelease      ProcessorStage = "release"
)

// ProcessorJournal preserves the legacy processor contract while allowing the
// passive-only WAL adapter. Private methods keep proof-bearing mutations inside
// this package; callers assign either *Journal or *PassiveWALJournal.
type ProcessorJournal interface {
	Load(string) (State, error)
	load(string) (State, error)
	loadPendingStatus(string) (State, error)
	setAckWithProof(string, Lane, Status, string) error
	AbortUnsentAttempt(string, Lane) error
	Release(string) error
}

type Processor struct {
	Journal ProcessorJournal
	Writer  Writer
	// Observer must be concurrency-safe, nonblocking, and perform no I/O. An empty
	// lane denotes whole-segment finalization. Errors are for counting, not logging
	// evidence or request contents. Nil preserves existing processor behavior.
	Observer func(Lane, ProcessorStage, time.Duration, error)
	// SinkTimeout starts after local source recovery and fsynced attempt state.
	// A slow journal disk must not consume the database request's own budget.
	SinkTimeout time.Duration
	// ProjectionRetryTimeout bounds reconciliation after an ambiguous projection
	// attempt. Other lanes and the first write retain their normal budget.
	ProjectionRetryTimeout time.Duration
	// FinalizeTimeout covers bounded receipt confirmation after all sinks ack.
	// It may need more disk I/O than one archive or projection request.
	FinalizeTimeout time.Duration
}

func (p Processor) observe(lane Lane, stage ProcessorStage, started time.Time, err error) {
	if p.Observer != nil {
		p.Observer(lane, stage, time.Since(started), err)
	}
}

func (p Processor) load(id string, lane Lane, statusOnly, sourceRaw bool) (State, error) {
	started := time.Now()
	var state State
	var err error
	switch {
	case statusOnly:
		state, err = p.Journal.loadPendingStatus(id)
	case sourceRaw:
		state, err = p.Journal.Load(id)
	default:
		state, err = p.Journal.load(id)
	}
	p.observe(lane, StageLoad, started, err)
	return state, err
}

func (p Processor) release(id string) error {
	started := time.Now()
	err := p.Journal.Release(id)
	p.observe("", StageRelease, started, err)
	return err
}

func (p Processor) sinkContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if p.SinkTimeout > 0 {
		return context.WithTimeout(ctx, p.SinkTimeout)
	}
	return context.WithCancel(ctx)
}

func (p Processor) finalizeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if p.FinalizeTimeout > 0 {
		return context.WithTimeout(ctx, p.FinalizeTimeout)
	}
	return p.sinkContext(ctx)
}

// DrainLane lets a source advance its projection even if a different segment
// is waiting on ClickHouse. A lane remains ordered by its own worker; the
// caller must not run two workers for the same source and lane.
func (p Processor) DrainLane(ctx context.Context, id string, lane Lane) error {
	if p.Journal == nil || p.Writer == nil {
		return errors.New("stream processor requires journal and writer")
	}
	// Only the archive sink needs the source-backed raw bytes. Search,
	// projection and finalization use the already verified event descriptor.
	if lane == Search {
		status, err := p.load(id, lane, true, false)
		if err != nil {
			return err
		}
		if !status.Released && status.Acks[Archive] != Acked && status.Acks[Archive] != NotApplicable {
			return ErrUnconfirmed
		}
	}
	state, err := p.load(id, lane, false, false)
	if err != nil {
		return err
	}
	searchFeaturesPending := lane == Search && state.Segment.SplitRiskFeatures && state.Acks[RiskFeatures] != Acked
	if state.Released || (state.Acks[lane] == Acked || state.Acks[lane] == NotApplicable) && !searchFeaturesPending {
		return nil
	}
	if !state.Committed && !state.ProcessingReady {
		return ErrUnconfirmed
	}
	if state.Segment.Quarantined {
		return ErrQuarantined
	}
	if lane == Archive && state.Segment.SourceBackedRaw {
		state, err = p.load(id, lane, false, true)
		if err != nil {
			return err
		}
		if state.Released || state.Acks[lane] == Acked || state.Acks[lane] == NotApplicable {
			return nil
		}
	}
	switch lane {
	case Archive:
		return p.runLane(ctx, id, lane, state, p.Writer.WriteBody, p.Writer.ReconcileBody)
	case Search:
		if state.Acks[Archive] != Acked && state.Acks[Archive] != NotApplicable {
			return ErrUnconfirmed
		}
		if state.Acks[Search] != Acked {
			if err := p.runLane(ctx, id, lane, state, p.Writer.WriteSearch, p.Writer.ReconcileSearch); err != nil {
				return err
			}
		}
		if !state.Segment.SplitRiskFeatures || state.Acks[RiskFeatures] == Acked {
			return nil
		}
		writer, ok := p.Writer.(RiskFeatureWriter)
		if !ok {
			return errors.New("stream risk-feature writer is not configured")
		}
		return p.runLane(ctx, id, RiskFeatures, state, writer.WriteRiskFeatures, writer.ReconcileRiskFeatures)
	case Projection:
		return p.runLane(ctx, id, lane, state, p.Writer.Project, p.Writer.ReconcileProjection)
	default:
		return fmt.Errorf("invalid stream lane %q", lane)
	}
}

// FinalizeAfterLanes is called by one finalizer after all required lanes ack.
// It never releases the durable body before cross-lane metadata is committed.
func (p Processor) FinalizeAfterLanes(ctx context.Context, id string) error {
	if p.Journal == nil || p.Writer == nil {
		return errors.New("stream processor requires journal and writer")
	}
	status, err := p.load(id, "", true, false)
	if err != nil {
		return err
	}
	if !status.Committed || status.Segment.Quarantined {
		return ErrUnconfirmed
	}
	for _, lane := range requiredLanes(status.Segment) {
		if status.Acks[lane] != Acked && status.Acks[lane] != NotApplicable {
			return ErrUnconfirmed
		}
	}
	state, err := p.load(id, "", false, false)
	if err != nil {
		return err
	}
	if !state.Committed || state.Segment.Quarantined {
		return ErrUnconfirmed
	}
	for _, lane := range requiredLanes(state.Segment) {
		if state.Acks[lane] != Acked && state.Acks[lane] != NotApplicable {
			return ErrUnconfirmed
		}
	}
	if finalizer, ok := p.Writer.(SegmentFinalizer); ok {
		started := time.Now()
		sinkCtx, cancel := p.finalizeContext(ctx)
		err := finalizer.FinalizeSegment(sinkCtx, id, state.Segment)
		cancel()
		p.observe("", StageFinalize, started, err)
		if err != nil {
			return fmt.Errorf("stream segment %s finalization: %w", id, err)
		}
	}
	return p.release(id)
}

func (p Processor) Drain(ctx context.Context, id string) error {
	if p.Journal == nil || p.Writer == nil {
		return errors.New("stream processor requires journal and writer")
	}
	state, err := p.load(id, "", false, false)
	if err != nil {
		return err
	}
	if state.Released {
		return nil
	}
	if state.Segment.Quarantined {
		return ErrQuarantined
	}
	if !state.Committed {
		return ErrUnconfirmed
	}
	archiveState := state
	if state.Acks[Archive] != Acked && state.Acks[Archive] != NotApplicable && state.Segment.SourceBackedRaw {
		archiveState, err = p.load(id, Archive, false, true)
		if err != nil {
			return err
		}
	}
	var failures []error
	// Projection must be able to make the current state visible even when the
	// independent ClickHouse archive call is slow or its result is unknown.
	var projectionDone chan error
	if state.Acks[Projection] != Acked && state.Acks[Projection] != NotApplicable {
		projectionDone = make(chan error, 1)
		go func() {
			projectionDone <- p.runLane(ctx, id, Projection, state, p.Writer.Project, p.Writer.ReconcileProjection)
		}()
	}
	if state.Acks[Archive] != Acked && state.Acks[Archive] != NotApplicable {
		if err := p.runLane(ctx, id, Archive, archiveState, p.Writer.WriteBody, p.Writer.ReconcileBody); err != nil {
			failures = append(failures, err)
		}
	}
	if projectionDone != nil {
		if err := <-projectionDone; err != nil {
			failures = append(failures, err)
		}
	}
	state, err = p.load(id, "", false, false)
	if err != nil {
		return err
	}
	if state.Acks[Archive] == Acked || state.Acks[Archive] == NotApplicable {
		if err := p.DrainLane(ctx, id, Search); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	state, err = p.load(id, "", false, false)
	if err != nil {
		return err
	}
	for _, lane := range requiredLanes(state.Segment) {
		if state.Acks[lane] != Acked && state.Acks[lane] != NotApplicable {
			return ErrUnconfirmed
		}
	}
	if finalizer, ok := p.Writer.(SegmentFinalizer); ok {
		started := time.Now()
		sinkCtx, cancel := p.finalizeContext(ctx)
		err := finalizer.FinalizeSegment(sinkCtx, id, state.Segment)
		cancel()
		p.observe("", StageFinalize, started, err)
		if err != nil {
			return fmt.Errorf("stream segment %s finalization: %w", id, err)
		}
	}
	return p.release(id)
}

func (p Processor) runLane(ctx context.Context, id string, lane Lane, state State,
	write, reconcile func(context.Context, string, Segment) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var err error
	markedAttempt := false
	reportSlow := func(stage string, started time.Time) {
		if elapsed := time.Since(started); p.Observer == nil && elapsed >= time.Second {
			log.Printf("stream lane stage segment=%s lane=%s stage=%s duration=%s", id, lane, stage, elapsed.Round(time.Millisecond))
		}
	}
	switch state.Acks[lane] {
	case Pending:
		if preflight, ok := p.Writer.(LanePreflight); ok {
			started := time.Now()
			err := preflight.Preflight(lane, state.Segment)
			p.observe(lane, StagePreflight, started, err)
			if err != nil {
				return fmt.Errorf("stream lane %s local preflight: %w", lane, err)
			}
		}
		if lane != Projection || !state.Segment.SourceBackedRaw {
			started := time.Now()
			err = p.Journal.setAckWithProof(id, lane, Attempted, state.ContentSHA256)
			p.observe(lane, StageBeginAttempt, started, err)
			if err != nil {
				return errors.Join(err, p.Journal.AbortUnsentAttempt(id, lane))
			}
			markedAttempt = true
			reportSlow("begin_attempt", started)
			if err := ctx.Err(); err != nil {
				return errors.Join(err, p.Journal.AbortUnsentAttempt(id, lane))
			}
		}
		started := time.Now()
		sinkCtx, cancel := p.sinkContext(ctx)
		err = write(sinkCtx, id, state.Segment)
		cancel()
		p.observe(lane, StageWrite, started, err)
		reportSlow("write", started)
		var unsent *UnsentLaneError
		if markedAttempt && errors.As(err, &unsent) {
			return errors.Join(err, p.Journal.AbortUnsentAttempt(id, lane))
		}
	case Attempted:
		started := time.Now()
		var sinkCtx context.Context
		var cancel context.CancelFunc
		if lane == Projection && p.ProjectionRetryTimeout > 0 {
			sinkCtx, cancel = context.WithTimeout(ctx, p.ProjectionRetryTimeout)
		} else {
			sinkCtx, cancel = p.sinkContext(ctx)
		}
		err = reconcile(sinkCtx, id, state.Segment)
		cancel()
		p.observe(lane, StageReconcile, started, err)
		reportSlow("reconcile", started)
	default:
		return fmt.Errorf("stream lane %s has invalid status %q", lane, state.Acks[lane])
	}
	if err != nil {
		return fmt.Errorf("stream lane %s segment %s: %w", lane, id, err)
	}
	started := time.Now()
	err = p.Journal.setAckWithProof(id, lane, Acked, state.ContentSHA256)
	p.observe(lane, StageAck, started, err)
	reportSlow("ack", started)
	return err
}
