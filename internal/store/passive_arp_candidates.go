package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

type passiveARPCandidate struct {
	MAC       string    `json:"mac"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ensurePassiveARPCandidateEndpoints promotes only accepted ARP sender MACs to
// low-confidence identities. A single bounded statement precedes observation
// linking, so the first ARP evidence can link without waiting for a lease or
// for another packet. It never turns a registered IP into an observed address.
func ensurePassiveARPCandidateEndpoints(ctx context.Context, db passiveDiscoveryDB, events []normalized.Event, scope passiveDiscoveryScope) error {
	byMAC := make(map[string]passiveARPCandidate)
	for _, event := range events {
		if !strings.EqualFold(event.SourceEventType, "arp") {
			continue
		}
		observation, reason := passiveObservation(event, scope)
		if reason != "" || observation.Origin != "arp" || observation.MAC == "" {
			continue
		}
		candidate, exists := byMAC[observation.MAC]
		if !exists {
			byMAC[observation.MAC] = passiveARPCandidate{MAC: observation.MAC, FirstSeen: observation.ObservedAt, LastSeen: observation.ObservedAt}
			continue
		}
		if observation.ObservedAt.Before(candidate.FirstSeen) {
			candidate.FirstSeen = observation.ObservedAt
		}
		if observation.ObservedAt.After(candidate.LastSeen) {
			candidate.LastSeen = observation.ObservedAt
		}
		byMAC[observation.MAC] = candidate
	}
	if len(byMAC) == 0 {
		return nil
	}
	candidates := make([]passiveARPCandidate, 0, len(byMAC))
	for _, candidate := range byMAC {
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].MAC < candidates[j].MAC })
	raw, _ := json.Marshal(candidates)
	_, err := db.ExecContext(ctx, `
INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,identity_confidence,attributes)
SELECT 'mac:'||incoming.mac,incoming.mac,'endpoint',incoming.first_seen,incoming.last_seen,0.55,
       '{"identity_source":"passive_arp_sender"}'::jsonb
FROM jsonb_to_recordset($1::jsonb) AS incoming(mac text,first_seen timestamptz,last_seen timestamptz)
ORDER BY incoming.mac
ON CONFLICT(endpoint_id) DO UPDATE SET
  first_seen=COALESCE(endpoint_entities.first_seen,EXCLUDED.first_seen),
  last_seen=GREATEST(endpoint_entities.last_seen,EXCLUDED.last_seen),
  identity_confidence=GREATEST(endpoint_entities.identity_confidence,EXCLUDED.identity_confidence),
  attributes=CASE WHEN endpoint_entities.last_seen IS NULL THEN endpoint_entities.attributes || '{"identity_source":"passive_arp_sender"}'::jsonb ELSE endpoint_entities.attributes END,
  updated_at=now()
WHERE (endpoint_entities.attributes->>'identity_source'='passive_arp_sender' OR endpoint_entities.last_seen IS NULL)
  AND (endpoint_entities.last_seen IS NULL OR endpoint_entities.last_seen<EXCLUDED.last_seen-interval '5 minutes')`, string(raw))
	return err
}
