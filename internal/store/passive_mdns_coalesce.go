package store

import (
	"strings"

	"proxy-sentinel/internal/normalized"
)

type passiveMDNSKey struct {
	sensor, iface, sender, recordType, name, value string
}

// passiveCoalescedMDNSIndexes retains the first and last copy of an unchanged
// positive-TTL record in each batch. A withdrawal is a barrier. The original
// standard events stay in ClickHouse; only redundant projection work is
// coalesced. Sender is part of the key so distinct announcers remain visible.
func passiveCoalescedMDNSIndexes(events []normalized.Event) map[int]bool {
	groups := make([][]int, 0)
	current := map[passiveMDNSKey][]int{}
	for i, event := range events {
		key, ok := passiveMDNSCoalesceKey(event)
		if !ok {
			continue
		}
		if passiveTTL(event.Payload, 120) == 0 {
			if prior := current[key]; len(prior) > 0 {
				groups = append(groups, prior)
				delete(current, key)
			}
			continue
		}
		current[key] = append(current[key], i)
	}
	for _, indexes := range current {
		groups = append(groups, indexes)
	}
	coalesced := make(map[int]bool)
	for _, indexes := range groups {
		if len(indexes) <= 2 {
			continue
		}
		for _, index := range indexes[1 : len(indexes)-1] {
			coalesced[index] = true
		}
	}
	return coalesced
}

func passiveMDNSCoalesceKey(event normalized.Event) (passiveMDNSKey, bool) {
	if event.SourceEventType != "mdns" || passiveString(event.Payload, "is_response") != "true" {
		return passiveMDNSKey{}, false
	}
	typeName := strings.ToUpper(passiveString(event.Payload, "record_type"))
	name := strings.ToLower(strings.TrimSuffix(passiveString(event.Payload, "record_name"), "."))
	value := passiveString(event.Payload, "record_address")
	switch typeName {
	case "A", "AAAA":
	case "SRV", "PTR":
		value = strings.ToLower(strings.TrimSuffix(passiveString(event.Payload, "service_target"), "."))
	case "TXT":
		value = passiveString(event.Payload, "record_text")
	default:
		return passiveMDNSKey{}, false
	}
	sensor := passiveString(event.Observer, "sensor_id")
	if sensor == "" || name == "" || value == "" {
		return passiveMDNSKey{}, false
	}
	return passiveMDNSKey{sensor: sensor, iface: passiveInterface(event), sender: passiveString(event.Subject, "ip"), recordType: typeName, name: name, value: value}, true
}
