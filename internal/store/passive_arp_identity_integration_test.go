package store

import (
	"context"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestPassiveARPRegistersCandidateIdentityBeforeLinking(t *testing.T) {
	ctx := context.Background()
	pg := privateMigratedTestPostgres(t)
	store := &DBStore{pg: pg}
	endpointID := "mac:02:00:00:20:40:02"
	base := time.Now().UTC().Truncate(time.Second)
	first := passiveTestEvent("arp", "192.168.50.12", "02:00:00:20:40:02", map[string]any{})
	first.EventID = "arp-candidate-a"
	first.Timestamp = base.Format(time.RFC3339Nano)
	second := first
	second.EventID = "arp-candidate-b"
	second.Timestamp = base.Add(time.Second).Format(time.RFC3339Nano)
	second.Subject = map[string]any{"ip": "192.168.50.13", "mac": "02:00:00:20:40:02", "campus_id": "office-30"}
	outside := first
	outside.EventID = "arp-candidate-outside"
	outside.Subject = map[string]any{"ip": "198.51.100.1", "mac": "02:00:00:20:40:03", "campus_id": "office-30"}
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/16")
	if _, err := store.processPassiveDiscoveryBatch(ctx, []normalized.Event{first, second, outside}, scope); err != nil {
		t.Fatal(err)
	}
	var mac, source string
	var confidence float64
	if err := pg.db.QueryRowContext(ctx, `SELECT primary_mac,identity_confidence,attributes->>'identity_source' FROM endpoint_entities WHERE endpoint_id=$1`, endpointID).Scan(&mac, &confidence, &source); err != nil || mac != "02:00:00:20:40:02" || source != "passive_arp_sender" || confidence <= 0 || confidence >= 0.8 {
		t.Fatalf("ARP candidate identity: mac=%q confidence=%v source=%q err=%v", mac, confidence, source, err)
	}
	var links int
	if err := pg.db.QueryRowContext(ctx, `SELECT count(*) FROM discovery_identity_links l JOIN discovery_observations o ON o.id=l.observation_id
		WHERE l.endpoint_id=$1 AND o.data->>'event_id' IN ($2,$3)`, endpointID, first.EventID, second.EventID).Scan(&links); err != nil || links != 2 {
		t.Fatalf("ARP evidence links=%d err=%v", links, err)
	}
	var outsideExists bool
	if err := pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM endpoint_entities WHERE endpoint_id='mac:02:00:00:20:40:03')`).Scan(&outsideExists); err != nil || outsideExists {
		t.Fatalf("out-of-scope ARP created identity: exists=%v err=%v", outsideExists, err)
	}
}
