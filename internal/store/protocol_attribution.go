package store

import (
	"context"
	"net"

	"proxy-sentinel/internal/normalized"
)

// Protocol self-report (HTTP Server headers, TLS certificate subjects, JA3/JA4)
// identifies a device, but Zeek cannot attach link-layer addresses to those
// logs. Attribute them through the same unique-lease rule already used for
// software announcements.
//
// Derived events are written to PostgreSQL only. They are never written back to
// ClickHouse normalized_events, so evidence aggregation, risk scoring,
// shared-access evaluation and router recognition stay untouched.
const (
	protocolAttributionOrigin     = "protocol-self-report"
	protocolAttributionEventPref  = "protocol:"
	protocolAttributionResolveMax = 500
)

// protocolAttributionPayloadKeys lists the payload keys per normalized event
// type that carry device self-report. Events without any of these keys are not
// attributed.
var protocolAttributionPayloadKeys = map[string][]string{
	"http": {"server", "title"},
	"tls":  {"certificate_subject", "certificate_issuer", "certificate_san", "ja3", "ja4"},
}

// protocolDeviceEvents resolves a unique DHCP lease for source events that lack
// a link-layer address and returns derived device events. Unresolved and
// ambiguous observations are dropped; they are never guessed from the IP alone.
//
// The number of lease lookups per batch is bounded because a reconciliation
// batch can carry ten thousand events. Repeated lookups inside the batch reuse
// the previous answer for the same sensor, campus, address and event time.
func (s *PostgresStore) protocolDeviceEvents(ctx context.Context, events []normalized.Event) ([]normalized.Event, error) {
	derived := make([]normalized.Event, 0)
	attempts := 0
	type resolveKey struct{ sensor, campus, ip, timestamp string }
	cache := map[resolveKey]IdentityAttribution{}
	for _, event := range events {
		if attempts >= protocolAttributionResolveMax {
			break
		}
		keys, ok := protocolAttributionPayloadKeys[event.Type]
		if !ok || stringFromMap(event.Subject, "mac") != "" {
			continue
		}
		payload := protocolAttributionPayload(event, keys)
		if payload == nil {
			continue
		}
		sensor := stringFromMap(event.Observer, "sensor_id")
		ip := stringFromMap(event.Subject, "ip")
		// An empty or unparsable address would fail the inet cast and abort the
		// whole batch, so such events are skipped instead.
		if sensor == "" || net.ParseIP(ip) == nil {
			continue
		}
		campus := firstNonEmpty(stringFromMap(event.Subject, "campus_id"), stringFromMap(event.Payload, "campus_id"))
		key := resolveKey{sensor: sensor, campus: campus, ip: ip, timestamp: event.Timestamp}
		owner, cached := cache[key]
		if !cached {
			attempts++
			resolved, found, err := s.ResolveDeviceAt(ctx, DomainObservation{
				IP:        ip,
				Timestamp: event.Timestamp,
				SensorID:  sensor,
				CampusID:  campus,
			})
			if err != nil {
				return nil, err
			}
			if !found || resolved.Conflict {
				cache[key] = IdentityAttribution{Conflict: true}
				continue
			}
			owner = resolved
			cache[key] = owner
		}
		if owner.Conflict {
			continue
		}
		mac := owner.EndpointID
		if len(mac) <= len("mac:") || mac[:len("mac:")] != "mac:" {
			continue
		}
		derived = append(derived, protocolDeviceEvent(event, mac[len("mac:"):], payload))
	}
	return derived, nil
}

// protocolAttributionPayload keeps only the whitelisted self-report fields so a
// derived event cannot leak unrelated payload into device recognition.
func protocolAttributionPayload(event normalized.Event, keys []string) map[string]any {
	payload := map[string]any{}
	for _, key := range keys {
		if value := stringFromMap(event.Payload, key); value != "" {
			payload[key] = value
		}
	}
	if len(payload) == 0 {
		return nil
	}
	payload["origin"] = event.Type
	payload["derived"] = protocolAttributionOrigin
	if campus := firstNonEmpty(stringFromMap(event.Subject, "campus_id"), stringFromMap(event.Payload, "campus_id")); campus != "" {
		payload["campus_id"] = campus
	}
	if vlan := stringFromMap(event.Payload, "vlan"); vlan != "" {
		payload["vlan"] = vlan
	}
	return payload
}

func protocolDeviceEvent(event normalized.Event, mac string, payload map[string]any) normalized.Event {
	subject := map[string]any{"mac": mac, "entity_role": "endpoint"}
	if ip := stringFromMap(event.Subject, "ip"); ip != "" {
		subject["ip"] = ip
	}
	if campus, ok := payload["campus_id"]; ok {
		subject["campus_id"] = campus
	}
	flow := map[string]any{}
	for _, key := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "proto", "direction"} {
		if value, ok := event.Flow[key]; ok {
			flow[key] = value
		}
	}
	rawRef := map[string]any{"backend": event.Source, "derived_from": event.EventID, "reason": protocolAttributionOrigin}
	if event.SourceEventType != "" {
		rawRef["log"] = event.SourceEventType
	}
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         protocolAttributionEventPref + shortHash(event.Type+"|"+event.EventID),
		Source:          event.Source,
		SourceEventType: event.SourceEventType,
		Type:            "device",
		Timestamp:       event.Timestamp,
		Observer:        event.Observer,
		Subject:         subject,
		Flow:            flow,
		Payload:         payload,
		Confidence:      0.7,
		RawRef:          rawRef,
	}
}

// WriteProtocolDeviceEvents materializes derived protocol self-report events
// into endpoint identities, device profiles and device signal facts in one
// transaction. It deliberately skips policy identity observations and never
// touches ClickHouse.
func (s *PostgresStore) WriteProtocolDeviceEvents(ctx context.Context, events []normalized.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state := BuildIdentityState(events)
	if err = writeIdentityState(ctx, tx, state); err != nil {
		return err
	}
	if err = writeEndpointDeviceProfiles(ctx, tx, state); err != nil {
		return err
	}
	for _, item := range BuildDeviceInventories("latest-run", events, nil) {
		for _, signal := range item.Signals {
			if err = upsertDeviceSignalFact(ctx, tx, s.sensorID, signal); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
