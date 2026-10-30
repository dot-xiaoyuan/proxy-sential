package discovery

import (
	"errors"
	"strings"

	"proxy-sentinel/internal/normalized"
)

// StreamFactIdentity adapts one normalized discovery event and returns the
// device/fact keys plus the observation used by the legacy projection. It is
// the single shared identity path for the new shadow projector; it does not
// write any state.
func StreamFactIdentity(event normalized.Event) (string, string, Observation, error) {
	var zero Observation
	adapted, err := AdaptDiscoveryEvent(event)
	if err != nil {
		return "", "", zero, err
	}
	observation, err := FromEvent(adapted)
	if err != nil {
		return "", "", zero, err
	}
	if observation.IP != "" && !IsPrivateDiscoveryAddress(observation.IP) {
		return "", "", zero, errors.New("discovery address is not private")
	}
	device := discoveryStateKey(observation)
	fact := discoveryFactKey(observation)
	if strings.TrimSpace(device) == "" || strings.TrimSpace(fact) == "" {
		return "", "", zero, errors.New("discovery identity is empty")
	}
	return device, fact, observation, nil
}
