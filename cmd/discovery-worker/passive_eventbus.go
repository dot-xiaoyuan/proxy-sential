package main

import (
	"context"
	"errors"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/eventbus"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

// Persist the canary decision inside the immutable segment before source
// commit. Recovery must follow the recorded decision, not today's env value.
type passiveReliableCaptureJournal struct {
	discovery.PassiveStreamJournal
}

func (j passiveReliableCaptureJournal) AppendAndCommitPassive(segment streamlog.Segment) (string, error) {
	segment.EventBusRequired = true
	return j.PassiveStreamJournal.AppendAndCommitPassive(segment)
}

type passiveEventBusLaneWriter struct {
	store.StreamLaneWriter
	bus *eventbus.ReliablePublisher
}

func (w passiveEventBusLaneWriter) Preflight(lane streamlog.Lane, segment streamlog.Segment) error {
	if lane == streamlog.EventBus {
		if w.bus == nil {
			return errors.New("reliable event bus producer is not configured")
		}
		return w.bus.Preflight(streamlog.SourceSegmentID(segment), segment)
	}
	return w.StreamLaneWriter.Preflight(lane, segment)
}

func (w passiveEventBusLaneWriter) WriteEventBus(ctx context.Context, id string, segment streamlog.Segment) error {
	if w.bus == nil {
		return errors.New("reliable event bus producer is not configured")
	}
	return w.bus.Publish(ctx, id, segment)
}

// Broker outcome after a timeout is ambiguous. Reconciliation sends the same
// stable event IDs again, and the journal remains pending until every callback
// confirms. Consumers must handle duplicates across producer sessions.
func (w passiveEventBusLaneWriter) ReconcileEventBus(ctx context.Context, id string, segment streamlog.Segment) error {
	return w.WriteEventBus(ctx, id, segment)
}
