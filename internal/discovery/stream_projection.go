package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

// Stream receipts are distinct from current facts: two identical broadcasts
// at different source positions have two receipts and one current fact.
type streamDiscoveryReceipt struct {
	Scope    string    `json:"scope_id"`
	Key      string    `json:"event_key"`
	Hash     string    `json:"content_sha256"`
	Accepted time.Time `json:"accepted_at"`
	Result   string    `json:"result"`
}

type streamDiscoveryFact struct {
	Epoch             string            `json:"epoch"`
	Device            string            `json:"device_key"`
	Key               string            `json:"fact_key"`
	Scope             string            `json:"scope_id"`
	Source            string            `json:"source_id"`
	Protocol          string            `json:"protocol"`
	ServiceInstance   string            `json:"service_instance"`
	Event             string            `json:"event_key"`
	EvidenceEvent     string            `json:"visible_event_key"`
	Revision          int64             `json:"revision"`
	Observed          time.Time         `json:"observed_at"`
	FirstObserved     time.Time         `json:"first_observed_at"`
	ValidUntil        time.Time         `json:"valid_until"`
	Withdrawn         bool              `json:"withdrawn"`
	SemanticHash      string            `json:"semantic_hash"`
	IP                string            `json:"ip"`
	MAC               string            `json:"mac"`
	Name              string            `json:"name"`
	Manufacturer      string            `json:"manufacturer"`
	Model             string            `json:"model_name"`
	DeviceType        string            `json:"device_type"`
	CandidateType     string            `json:"candidate_type"`
	CandidateReason   string            `json:"candidate_reason"`
	Excluded          bool              `json:"excluded"`
	Capabilities      []string          `json:"capabilities"`
	RecognitionFields map[string]string `json:"recognition_fields"`
	AddressBinding    bool              `json:"address_binding"`
	Sensor            string            `json:"sensor_id"`
	Site              string            `json:"site"`
	Domain            string            `json:"domain"`
	VLAN              string            `json:"vlan"`
	VRF               string            `json:"vrf"`
	Interface         string            `json:"interface_name"`
}

type streamPreparedDiscovery struct {
	Protocol    string
	Parsed      bool
	Receipt     streamDiscoveryReceipt
	Fact        streamDiscoveryFact
	HasFact     bool
	Observation Observation
}

type streamFactDecision struct {
	Result         string
	WriteFact      bool
	VisibleChanged bool
	EvidenceEvent  string
}

func prepareStreamDiscovery(segment streamlog.Segment) ([]streamPreparedDiscovery, error) {
	if segment.Epoch == "" || segment.AcceptedAt.IsZero() || len(segment.Events) == 0 {
		return nil, errors.New("stream discovery segment requires epoch, acceptance time and events")
	}
	prepared := make([]streamPreparedDiscovery, 0, len(segment.Events))
	seen := make(map[string]string, len(segment.Events))
	for _, event := range segment.Events {
		if !normalized.IsDiscoveryProjectionEvent(event) {
			continue
		}
		if event.EventID == "" || event.Timestamp == "" {
			return nil, errors.New("stream discovery event lacks fixed identity or time")
		}
		scope := str(event.Observer, "capture_scope_id")
		if scope == "" {
			return nil, fmt.Errorf("stream discovery event %s lacks capture scope", event.EventID)
		}
		body, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		key := segment.Epoch + ":" + event.EventID
		identity := scope + "\x00" + key
		if prior, found := seen[identity]; found {
			if prior != hash {
				return nil, streamlog.ErrContentConflict
			}
			return nil, fmt.Errorf("duplicate event key within immutable stream segment: %w", streamlog.ErrContentConflict)
		}
		seen[identity] = hash
		item := streamPreparedDiscovery{Receipt: streamDiscoveryReceipt{Scope: scope, Key: key, Hash: hash, Accepted: segment.AcceptedAt, Result: "applied"}}
		item.Protocol = firstText(str(event.Payload, "origin"), event.SourceEventType)
		adapted, err := AdaptDiscoveryEvent(event)
		if err == nil {
			item.Observation, err = FromEvent(adapted)
		}
		if err != nil {
			item.Receipt.Result = "rejected: " + err.Error()
			prepared = append(prepared, item)
			continue
		}
		item.Parsed = true
		o := item.Observation
		if o.IP != "" && !IsPrivateDiscoveryAddress(o.IP) {
			item.Receipt.Result = "outside_private_scope"
			prepared = append(prepared, item)
			continue
		}
		semantic := o
		semantic.ID, semantic.EventID, semantic.SnapshotID = "", "", ""
		semantic.ObservedAt, semantic.ValidUntil, semantic.ReportedAt = time.Time{}, time.Time{}, nil
		payload := make(map[string]any, len(o.Evidence.Payload))
		for field, value := range o.Evidence.Payload {
			if field != "ttl" && field != "record_ttl" && field != "revision" {
				payload[field] = value
			}
		}
		semantic.Evidence = normalized.Event{Payload: payload}
		candidate, reason := observationIoTType(o)
		item.Fact = streamDiscoveryFact{
			Epoch: segment.Epoch, Device: discoveryStateKey(o), Key: discoveryFactKey(o), Scope: scope,
			Source: o.SourceID, Protocol: o.Origin, ServiceInstance: serviceInstance(o), Event: key, EvidenceEvent: key,
			Revision: int64(number(event.Payload, "revision")), Observed: o.ObservedAt, FirstObserved: o.ObservedAt, ValidUntil: o.ValidUntil,
			Withdrawn: o.Withdrawn, SemanticHash: contentHash(semantic), IP: o.IP, MAC: o.MAC,
			Name: o.Name, Manufacturer: o.Manufacturer, Model: o.ModelName, DeviceType: o.DeviceType,
			CandidateType: candidate, CandidateReason: reason, Excluded: excludedStreamDeviceType(o.DeviceType),
			Capabilities: append([]string(nil), o.Capabilities...), AddressBinding: o.Evidence.Payload["address_binding"] == true, Sensor: o.Node, Site: o.Site,
			RecognitionFields: streamRecognitionFields(o),
			Domain:            o.Domain, VLAN: o.VLAN, VRF: o.VRF, Interface: o.Interface,
		}
		if segment.Source == "passive-discovery" {
			if first, ok := event.RawRef["coalesced_first_observed_at"].(string); ok {
				if firstAt, parseErr := time.Parse(time.RFC3339Nano, first); parseErr == nil &&
					!firstAt.After(o.ObservedAt) && o.ObservedAt.Sub(firstAt) <= passiveCaptureCoalesceWindow {
					item.Fact.FirstObserved = firstAt
				}
			}
		}
		item.HasFact = true
		prepared = append(prepared, item)
	}
	return prepared, nil
}

func excludedStreamDeviceType(kind string) bool {
	switch strings.ToLower(kind) {
	case "mobile", "phone", "desktop", "laptop", "computer", "server", "router", "switch", "access_point", "firewall":
		return true
	}
	return false
}

func mergeStreamDiscoveryFact(previous *streamDiscoveryFact, next streamDiscoveryFact) streamFactDecision {
	if previous == nil {
		return streamFactDecision{Result: "applied", WriteFact: true, VisibleChanged: true, EvidenceEvent: next.Event}
	}
	prior := discoveryFactVersion{Event: previous.Event, Revision: previous.Revision, Observed: previous.Observed, Hash: previous.SemanticHash}
	current := discoveryFactVersion{Event: next.Event, Revision: next.Revision, Observed: next.Observed, Hash: next.SemanticHash}
	if !prior.supersededBy(current) {
		return streamFactDecision{Result: "late_history", EvidenceEvent: previous.EvidenceEvent}
	}
	if previous.SemanticHash == next.SemanticHash && previous.Withdrawn == next.Withdrawn {
		evidenceEvent := previous.EvidenceEvent
		if evidenceEvent == "" {
			evidenceEvent = previous.Event
		}
		return streamFactDecision{Result: "repeat_observation", WriteFact: true, EvidenceEvent: evidenceEvent}
	}
	if next.Withdrawn && !previous.Withdrawn {
		return streamFactDecision{Result: "withdrawn", WriteFact: true, VisibleChanged: true, EvidenceEvent: next.Event}
	}
	if previous.Withdrawn && !next.Withdrawn {
		return streamFactDecision{Result: "restored", WriteFact: true, VisibleChanged: true, EvidenceEvent: next.Event}
	}
	return streamFactDecision{Result: "corrected", WriteFact: true, VisibleChanged: true, EvidenceEvent: next.Event}
}
