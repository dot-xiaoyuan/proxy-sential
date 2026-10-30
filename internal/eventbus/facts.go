package eventbus

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

// Fact is one fact-level row in the shadow current-facts table. It carries the
// observation JSON for audit, but no query path reads this table yet.
type Fact struct {
	DeviceKey       string
	FactKey         string
	EventID         string
	SensorID        string
	SourceID        string
	Site            string
	Domain          string
	VLAN            string
	InterfaceName   string
	Protocol        string
	ServiceInstance string
	IP              string
	MAC             string
	ObservedAt      time.Time
	ValidUntil      time.Time
	Withdrawn       bool
	ContentHash     string
	Version         uint64
	Observation     []byte
	ConsumedAt      time.Time
}

// FactFromEnvelope uses the legacy discovery adapter for identity only. It does
// not write PostgreSQL or the legacy projection.
func FactFromEnvelope(envelope Envelope) (Fact, error) {
	if len(envelope.Event) == 0 {
		return Fact{}, errors.New("event bus envelope has no event body")
	}
	var event normalized.Event
	if err := json.Unmarshal(envelope.Event, &event); err != nil {
		return Fact{}, fmt.Errorf("decode discovery event body: %w", err)
	}
	deviceKey, factKey, observation, err := discovery.StreamFactIdentity(event)
	if err != nil {
		return Fact{}, fmt.Errorf("derive discovery fact identity: %w", err)
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		return Fact{}, fmt.Errorf("encode discovery observation: %w", err)
	}
	version := observation.ObservedAt.UnixNano()
	if version <= 0 {
		version = 1
	}
	return Fact{
		DeviceKey:       deviceKey,
		FactKey:         factKey,
		EventID:         envelope.EventID,
		SensorID:        observation.Node,
		SourceID:        observation.SourceID,
		Site:            observation.Site,
		Domain:          observation.Domain,
		VLAN:            observation.VLAN,
		InterfaceName:   observation.Interface,
		Protocol:        observation.Origin,
		ServiceInstance: factServiceInstance(observation),
		IP:              observation.IP,
		MAC:             observation.MAC,
		ObservedAt:      observation.ObservedAt.UTC(),
		ValidUntil:      observation.ValidUntil.UTC(),
		Withdrawn:       observation.Withdrawn,
		ContentHash:     envelope.ContentHash,
		Version:         uint64(version),
		Observation:     raw,
		ConsumedAt:      time.Now().UTC(),
	}, nil
}

func factServiceInstance(observation discovery.Observation) string {
	payload := observation.Evidence.Payload
	for _, key := range []string{"service_instance", "endpoint_reference", "usn", "service_type"} {
		if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
