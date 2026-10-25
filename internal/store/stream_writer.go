package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

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
		if segment.RiskFeaturesRequired {
			_, err := prepareStreamRiskFeatures(segment)
			return err
		}
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
	if !segment.RiskFeaturesRequired {
		return nil
	}
	return w.ClickHouse.WriteStreamRiskFeatures(ctx, id, segment)
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
		return streamlog.ErrUnconfirmed
	}
	if !segment.RiskFeaturesRequired {
		return nil
	}
	present, err = w.ClickHouse.VerifyStreamRiskFeatures(ctx, segment)
	if err != nil || !present {
		if err != nil {
			return err
		}
		return streamlog.ErrUnconfirmed
	}
	return nil
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
