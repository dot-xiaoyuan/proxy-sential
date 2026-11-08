package store

import (
	"encoding/json"
	"strings"

	"proxy-sentinel/internal/normalized"
)

// An unchanged ARP sender claim is useful at its first and last observation
// within a batch. The standard events, including the intervening timestamps
// and raw references, remain in ClickHouse. Keep the entire fact content in
// the key so a changed opcode, scope, VLAN or claim is never collapsed.
func passiveCoalescedARPIndexes(events []normalized.Event) map[int]bool {
	groups := make(map[string][]int)
	for i, event := range events {
		if !strings.EqualFold(event.SourceEventType, "arp") {
			continue
		}
		fact := event
		fact.EventID = ""
		fact.Timestamp = ""
		fact.RawRef = nil
		raw, err := json.Marshal(fact)
		if err != nil {
			continue
		}
		groups[string(raw)] = append(groups[string(raw)], i)
	}
	coalesced := make(map[int]bool)
	for _, indexes := range groups {
		for _, index := range indexes[1:max(1, len(indexes)-1)] {
			coalesced[index] = true
		}
	}
	return coalesced
}
