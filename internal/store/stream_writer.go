package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"proxy-sentinel/internal/streamlog"
)

var ErrStreamProjectorUnavailable = errors.New("stream projection is not configured")

type StreamProjector interface {
	ProjectStreamSegment(context.Context, string, streamlog.Segment) error
	ReconcileStreamProjection(context.Context, string, streamlog.Segment) error
}

type StreamArchiveConfirmer interface {
	MarkStreamArchiveConfirmed(context.Context, string, streamlog.Segment) error
}

type StreamRiskQueue interface {
	MarkStreamRiskSubjectsDirty(context.Context, string, streamlog.Segment) error
}

type StreamSharedQueue interface {
	MarkStreamSharedJobs(context.Context, string, streamlog.Segment) error
}

// StreamLaneWriter binds independently confirmed segment lanes to their
// storage owners. A selected fact cannot be silently marked projected when
// its PostgreSQL projector is unavailable.
type StreamLaneWriter struct {
	ClickHouse  *ClickHouseStore
	Projector   StreamProjector
	RiskQueue   StreamRiskQueue
	SharedQueue StreamSharedQueue
}

// Preflight performs only local validation. A failure here must leave the
// journal lane pending because no ClickHouse request has been attempted.
func (w StreamLaneWriter) Preflight(lane streamlog.Lane, segment streamlog.Segment) error {
	switch lane {
	case streamlog.Archive:
		if _, err := prepareStreamEvents(segment); err != nil {
			return err
		}
		if streamRawArchiveRequired(segment) {
			sum := sha256.Sum256(segment.Raw)
			if segment.RawSHA256 != hex.EncodeToString(sum[:]) {
				return streamlog.ErrContentConflict
			}
		}
	case streamlog.Search:
		if _, err := prepareStreamEvents(segment); err != nil {
			return err
		}
		if segment.RiskFeaturesRequired && !segment.SplitRiskFeatures {
			_, err := prepareStreamRiskFeatures(segment)
			return err
		}
	case streamlog.RiskFeatures:
		_, err := prepareStreamRiskFeatures(segment)
		return err
	}
	return nil
}

func (w StreamLaneWriter) WriteBody(ctx context.Context, id string, segment streamlog.Segment) error {
	if w.ClickHouse == nil {
		return errors.New("stream ClickHouse writer is unavailable")
	}
	return w.ClickHouse.WriteStreamBody(ctx, id, segment)
}

func (w StreamLaneWriter) ReconcileBody(ctx context.Context, id string, segment streamlog.Segment) error {
	if w.ClickHouse == nil {
		return errors.New("stream ClickHouse writer is unavailable")
	}
	// A client timeout can precede an async flush. A missing row at this instant
	// is not proof that the write failed; automatic partial replay with a new
	// token can create duplicate rows after the first flush completes.
	if streamRawArchiveRequired(segment) {
		present, err := w.ClickHouse.verifyStreamRaw(ctx, id, segment)
		if err != nil || !present {
			if err != nil {
				return err
			}
			return streamlog.ErrUnconfirmed
		}
	}
	present, err := w.ClickHouse.VerifyStreamBody(ctx, segment)
	if err != nil || !present {
		if err != nil {
			return err
		}
		return streamlog.ErrUnconfirmed
	}
	return nil
}

func (w StreamLaneWriter) WriteSearch(ctx context.Context, id string, segment streamlog.Segment) error {
	if w.ClickHouse == nil {
		return errors.New("stream ClickHouse writer is unavailable")
	}
	if err := w.ClickHouse.WriteStreamSearch(ctx, id, segment); err != nil {
		return err
	}
	if !segment.RiskFeaturesRequired || segment.SplitRiskFeatures {
		return nil
	}
	if err := w.ClickHouse.WriteStreamRiskFeatures(ctx, id, segment); err != nil {
		return err
	}
	// Search runs only after the authoritative body is acknowledged. Once
	// features are confirmed, its subjects can be queued without waiting for
	// unrelated device projection, journal acknowledgement or shared jobs.
	// The immutable segment remains retained until all lanes finalize.
	return w.enqueueRisk(ctx, id, segment)
}

func (w StreamLaneWriter) ReconcileSearch(ctx context.Context, id string, segment streamlog.Segment) error {
	if w.ClickHouse == nil {
		return errors.New("stream ClickHouse writer is unavailable")
	}
	present, err := w.ClickHouse.VerifyStreamSearch(ctx, segment)
	if err != nil || !present {
		if err != nil {
			return err
		}
		return fmt.Errorf("search index confirmation missing: %w", streamlog.ErrUnconfirmed)
	}
	if !segment.RiskFeaturesRequired || segment.SplitRiskFeatures {
		return nil
	}
	present, err = w.ClickHouse.VerifyStreamRiskFeatures(ctx, segment)
	if err != nil || !present {
		if err != nil {
			return err
		}
		return fmt.Errorf("legacy risk feature confirmation missing: %w", streamlog.ErrUnconfirmed)
	}
	return w.enqueueRisk(ctx, id, segment)
}

func (w StreamLaneWriter) WriteRiskFeatures(ctx context.Context, id string, segment streamlog.Segment) error {
	if w.ClickHouse == nil {
		return errors.New("stream ClickHouse writer is unavailable")
	}
	if !segment.SplitRiskFeatures || !segment.RiskFeaturesRequired {
		return errors.New("stream segment has no independent risk-feature sink")
	}
	if err := w.ClickHouse.WriteStreamRiskFeatures(ctx, id, segment); err != nil {
		return err
	}
	return w.enqueueRisk(ctx, id, segment)
}

func (w StreamLaneWriter) ReconcileRiskFeatures(ctx context.Context, id string, segment streamlog.Segment) error {
	if w.ClickHouse == nil {
		return errors.New("stream ClickHouse writer is unavailable")
	}
	if !segment.SplitRiskFeatures || !segment.RiskFeaturesRequired {
		return errors.New("stream segment has no independent risk-feature sink")
	}
	present, err := w.ClickHouse.VerifyStreamRiskFeatures(ctx, segment)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("risk feature confirmation missing: %w", streamlog.ErrUnconfirmed)
	}
	return w.enqueueRisk(ctx, id, segment)
}

func (w StreamLaneWriter) Project(ctx context.Context, id string, segment streamlog.Segment) error {
	if w.Projector == nil {
		return ErrStreamProjectorUnavailable
	}
	return w.Projector.ProjectStreamSegment(ctx, id, segment)
}

func (w StreamLaneWriter) ReconcileProjection(ctx context.Context, id string, segment streamlog.Segment) error {
	if w.Projector == nil {
		return ErrStreamProjectorUnavailable
	}
	return w.Projector.ReconcileStreamProjection(ctx, id, segment)
}

func (w StreamLaneWriter) FinalizeSegment(ctx context.Context, id string, segment streamlog.Segment) error {
	if segment.NeedsProjection {
		confirmer, ok := w.Projector.(StreamArchiveConfirmer)
		if !ok {
			return ErrStreamProjectorUnavailable
		}
		if err := confirmer.MarkStreamArchiveConfirmed(ctx, id, segment); err != nil {
			return err
		}
	}
	for _, event := range segment.Events {
		if event.Source == "handshake-sidecar" && (event.SourceEventType == "handshake" || event.SourceEventType == "capture_coverage") ||
			event.Source == "packet-sidecar" && (event.SourceEventType == "ieee1905_client_association" || event.SourceEventType == "ieee1905_client_snapshot" || event.SourceEventType == "capture_coverage") {
			if w.SharedQueue == nil {
				return ErrStreamProjectorUnavailable
			}
			if err := w.SharedQueue.MarkStreamSharedJobs(ctx, id, segment); err != nil {
				return err
			}
			break
		}
	}
	if segment.SplitRiskFeatures {
		// Its independently acknowledged feature step already includes the PG
		// wake receipt. Finalization cannot reach here until that ack is durable.
		return nil
	}
	return w.enqueueRisk(ctx, id, segment)
}

// Legacy finalization repeats this idempotent receipt. Split feature recovery
// owns both confirmation and the PG wake before acknowledging its own step.
func (w StreamLaneWriter) enqueueRisk(ctx context.Context, id string, segment streamlog.Segment) error {
	if !segment.RiskFeaturesRequired {
		return nil
	}
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil || len(features) == 0 {
		return err
	}
	if w.RiskQueue == nil {
		return ErrStreamProjectorUnavailable
	}
	return w.RiskQueue.MarkStreamRiskSubjectsDirty(ctx, id, segment)
}
