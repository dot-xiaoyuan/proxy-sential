package store

import (
	"context"
	"net"

	"proxy-sentinel/internal/normalized"
)

// Protocol evidence is directional: HTTP server headers and certificates
// identify the responder; JA3/JA4 identify the client. Each side must have its
// own unique lease before it can become device evidence.
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

// protocolAttributionObservations splits protocol evidence before lease lookup.
// Subject.ip in network events is usually the requester, never proof of a
// certificate's owner. A host-scoped x509 event is the only single-host case.
func protocolAttributionObservations(event normalized.Event) []normalized.Event {
	serverKeys := map[string][]string{
		"http": {"server", "title"},
		"tls":  {"certificate_subject", "certificate_issuer", "certificate_san"},
	}
	keys, ok := serverKeys[event.Type]
	if !ok {
		return nil
	}
	observations := make([]normalized.Event, 0, 2)
	add := func(ip, side string, keys []string) {
		if net.ParseIP(ip) == nil {
			return
		}
		payload := protocolAttributionPayload(event, keys)
		if payload == nil {
			return
		}
		payload["attribution_side"] = side
		observation := event
		observation.Subject = map[string]any{"ip": ip}
		observation.Payload = payload
		observations = append(observations, observation)
	}
	serverIP := stringFromMap(event.Flow, "dst_ip")
	if owner := stringFromMap(event.Payload, "certificate_owner_ip"); owner != "" {
		serverIP = owner
	} else if event.SourceEventType == "x509" && serverIP == stringFromMap(event.Flow, "src_ip") {
		// Legacy x509 normalization duplicated the requester into dst_ip when
		// no responder existed. That alone cannot establish certificate ownership.
		serverIP = ""
	}
	add(serverIP, "server", keys)
	if event.Type == "tls" && event.SourceEventType != "x509" {
		clientIP := firstNonEmpty(stringFromMap(event.Flow, "src_ip"), stringFromMap(event.Subject, "ip"))
		add(clientIP, "client", []string{"ja3", "ja4"})
	}
	return observations
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
	observations := make([]normalized.Event, 0, len(events))
	for _, event := range events {
		observations = append(observations, protocolAttributionObservations(event)...)
	}
	for _, event := range observations {
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
		payload["attribution_side"] = event.Payload["attribution_side"]
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
		EventID:         protocolAttributionEventPref + shortHash("v2|"+event.Type+"|"+event.EventID+"|"+stringFromMap(payload, "attribution_side")),
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
