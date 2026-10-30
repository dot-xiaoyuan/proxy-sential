package discovery

import (
	"net"
	"net/netip"
	"strings"

	"proxy-sentinel/internal/normalized"
)

// StreamPartitionKey returns the stable Kafka key for one discovery event.
// Device identity is preferred so events for the same device keep their order.
// If the event cannot be adapted, a scoped MAC/IP/event fallback is used; the
// caller records the source and never silently drops an event for lack of a
// device key.
func StreamPartitionKey(event normalized.Event) (key, source string) {
	if adapted, err := AdaptDiscoveryEvent(event); err == nil {
		if observation, err := FromEvent(adapted); err == nil {
			if device := discoveryStateKey(observation); device != "" {
				return device, "device"
			}
		}
	}
	scope := str(event.Observer, "capture_scope_id")
	if scope == "" {
		scope = str(event.Observer, "sensor_id")
	}
	if raw := str(event.Subject, "mac"); raw != "" {
		if mac, err := net.ParseMAC(raw); err == nil {
			return contentHash([]string{scope, "mac", strings.ToLower(mac.String())})[:32], "mac"
		}
	}
	if raw := str(event.Subject, "ip"); raw != "" {
		if addr, err := netip.ParseAddr(raw); err == nil {
			return contentHash([]string{scope, "ip", addr.Unmap().String()})[:32], "ip"
		}
	}
	if event.EventID != "" {
		return contentHash([]string{scope, "event", event.EventID})[:32], "event"
	}
	return "", ""
}
