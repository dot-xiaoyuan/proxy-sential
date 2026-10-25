package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// readStreamSharedRows pages a single business-key window through the narrow
// search row and resolves verified bodies in bounded groups. This is a
// compatibility bridge for the existing shared-access evaluator; it does not
// copy full event documents into another ClickHouse table.
func (s *DBStore) readStreamSharedRows(ctx context.Context, scope SharedObservationScope, scopeID, source, epoch, subject string, from, to time.Time) ([]sharedObservationEvent, []sharedAssociationEvent, error) {
	handshakes, associations, _, err := s.readStreamSharedRowsWithRefs(ctx, scope, scopeID, source, epoch, subject, from, to)
	return handshakes, associations, err
}

func (s *DBStore) readStreamSharedRowsWithRefs(ctx context.Context, scope SharedObservationScope, scopeID, source, epoch, subject string, from, to time.Time) ([]sharedObservationEvent, []sharedAssociationEvent, []StreamSharedSignalRef, error) {
	if s == nil || s.ch == nil {
		return nil, nil, nil, errors.New("shared stream reader needs ClickHouse")
	}
	const pageSize = 100
	const maxRows = 2000
	var handshakes []sharedObservationEvent
	var associations []sharedAssociationEvent
	var allRefs []StreamSharedSignalRef
	var after time.Time
	var afterKey string
	var afterHash string
	seen := map[string]StreamSharedSignalRef{}
	for {
		page, err := s.ch.ListStreamSharedSignalRefs(ctx, scope, scopeID, source, epoch, subject, from, to, after, afterKey, afterHash, pageSize)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(page) == 0 {
			break
		}
		unique := make([]StreamSharedSignalRef, 0, len(page))
		refs := make([]StreamBodyRef, 0, len(page))
		for _, item := range page {
			identity := item.Body.Scope + "\x00" + item.EventKey
			if prior, ok := seen[identity]; ok {
				if prior.Body != item.Body || !prior.ObservedAt.Equal(item.ObservedAt) || prior.SubjectIP != item.SubjectIP || prior.SubjectMAC != item.SubjectMAC || prior.Protocol != item.Protocol {
					return nil, nil, nil, streamlog.ErrContentConflict
				}
				continue
			}
			seen[identity] = item
			unique = append(unique, item)
			allRefs = append(allRefs, item)
			refs = append(refs, item.Body)
		}
		if len(seen) > maxRows {
			return nil, nil, nil, errors.New("shared signal window exceeds bound")
		}
		if len(refs) > 0 {
			bodies, err := s.ch.GetStreamEventsByRefs(ctx, refs)
			if err != nil {
				return nil, nil, nil, err
			}
			for _, item := range unique {
				event := bodies[item.Body]
				observed, parseErr := time.Parse(time.RFC3339Nano, event.Timestamp)
				if parseErr != nil || event.EventID == "" || item.EventKey != epoch+":"+event.EventID || event.Source != item.Source || event.SourceEventType != item.Protocol ||
					stringFromMap(event.Observer, "sensor_id") != item.SensorID || stringFromMap(event.Observer, "capture_scope_id") != item.Body.Scope ||
					stringFromMap(event.Observer, "collector_instance_id") != item.CollectorInstanceID ||
					stringFromMap(event.Subject, "campus_id") != item.CampusID || stringFromMap(event.Payload, "access_domain") != item.AccessDomain ||
					stringFromMap(event.Subject, "ip") != item.SubjectIP || stringFromMap(event.Subject, "mac") != item.SubjectMAC ||
					!observed.UTC().Truncate(time.Microsecond).Equal(item.ObservedAt) {
					return nil, nil, nil, streamlog.ErrContentConflict
				}
				payload, err := json.Marshal(event.Payload)
				if err != nil {
					return nil, nil, nil, err
				}
				base := sharedObservationEvent{PayloadVersions: 1, Timestamp: observed.UTC().Format(time.RFC3339Nano), EventID: event.EventID, Source: item.Source, Instance: item.CollectorInstanceID, IP: item.SubjectIP, Payload: string(payload)}
				if source == "handshake-sidecar" {
					handshakes = append(handshakes, base)
				} else {
					associations = append(associations, sharedAssociationEvent{sharedObservationEvent: base, MAC: item.SubjectMAC, Kind: item.Protocol})
				}
			}
		}
		last := page[len(page)-1]
		after, afterKey, afterHash = last.ObservedAt, last.EventKey, last.Body.SHA256
		if len(page) < pageSize {
			break
		}
	}
	return handshakes, associations, allRefs, nil
}
