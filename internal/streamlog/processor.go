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

type Processor struct {
	Journal *Journal
	Writer  Writer
	// SinkTimeout starts after local source recovery and fsynced attempt state.
	// A slow journal disk must not consume the database request's own budget.
	SinkTimeout time.Duration
	// FinalizeTimeout covers bounded receipt confirmation after all sinks ack.
	// It may need more disk I/O than one archive or projection request.
	FinalizeTimeout time.Duration
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
	state, err := p.Journal.load(id)
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
		state, err = p.Journal.Load(id)
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
	state, err := p.Journal.load(id)
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
		sinkCtx, cancel := p.finalizeContext(ctx)
		err := finalizer.FinalizeSegment(sinkCtx, id, state.Segment)
		cancel()
		if err != nil {
			return fmt.Errorf("stream segment %s finalization: %w", id, err)
		}
	}
	return p.Journal.Release(id)
}

func (p Processor) Drain(ctx context.Context, id string) error {
	if p.Journal == nil || p.Writer == nil {
		return errors.New("stream processor requires journal and writer")
	}
	state, err := p.Journal.load(id)
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
		archiveState, err = p.Journal.Load(id)
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
	state, err = p.Journal.load(id)
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
	state, err = p.Journal.load(id)
	if err != nil {
		return err
	}
	for _, lane := range requiredLanes(state.Segment) {
		if state.Acks[lane] != Acked && state.Acks[lane] != NotApplicable {
			return ErrUnconfirmed
		}
	}
	if finalizer, ok := p.Writer.(SegmentFinalizer); ok {
		sinkCtx, cancel := p.finalizeContext(ctx)
		err := finalizer.FinalizeSegment(sinkCtx, id, state.Segment)
		cancel()
		if err != nil {
			return fmt.Errorf("stream segment %s finalization: %w", id, err)
		}
	}
	return p.Journal.Release(id)
}

func (p Processor) runLane(ctx context.Context, id string, lane Lane, state State,
	write, reconcile func(context.Context, string, Segment) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var err error
	reportSlow := func(stage string, started time.Time) {
		if elapsed := time.Since(started); elapsed >= time.Second {
			log.Printf("stream lane stage segment=%s lane=%s stage=%s duration=%s", id, lane, stage, elapsed.Round(time.Millisecond))
		}
	}
	switch state.Acks[lane] {
	case Pending:
		if preflight, ok := p.Writer.(LanePreflight); ok {
			if err := preflight.Preflight(lane, state.Segment); err != nil {
				return fmt.Errorf("stream lane %s local preflight: %w", lane, err)
			}
		}
		if lane != Projection || !state.Segment.SourceBackedRaw {
			started := time.Now()
			if err = p.Journal.BeginAttempt(id, lane); err != nil {
				return errors.Join(err, p.Journal.AbortUnsentAttempt(id, lane))
			}
			reportSlow("begin_attempt", started)
			if err := ctx.Err(); err != nil {
				return errors.Join(err, p.Journal.AbortUnsentAttempt(id, lane))
			}
		}
		started := time.Now()
		sinkCtx, cancel := p.sinkContext(ctx)
		err = write(sinkCtx, id, state.Segment)
		cancel()
		reportSlow("write", started)
	case Attempted:
		started := time.Now()
		sinkCtx, cancel := p.sinkContext(ctx)
		err = reconcile(sinkCtx, id, state.Segment)
		cancel()
		reportSlow("reconcile", started)
	default:
		return fmt.Errorf("stream lane %s has invalid status %q", lane, state.Acks[lane])
	}
	if err != nil {
		return fmt.Errorf("stream lane %s segment %s: %w", lane, id, err)
	}
	started := time.Now()
	err = p.Journal.Ack(id, lane)
	reportSlow("ack", started)
	return err
}
