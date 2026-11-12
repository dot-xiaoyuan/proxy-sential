package discovery

import (
	"strings"
	"testing"
	"time"
)

func TestIndexedSADPDisplayAssociationRequiresIndependentCurrentIdentity(t *testing.T) {
	selection, err := buildIndexedDeviceSelection(DeviceQuery{Mode: "passive"})
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []string{
		"trusted_address AS MATERIALIZED",
		"v.data->>'ip'=m.data->>'ip' AND v.observed_at<=now() AND v.valid_until>now()",
		"HAVING count(DISTINCT lower(v.data->>'mac'))=1",
		"m.origin='sadp' AND NOT m.withdrawn AND m.observed_at<=now() AND m.observed_at>=now()-interval '30 days'",
		"coalesce(m.data->>'node','')<>'' AND coalesce(m.data->>'site','')<>'' AND coalesce(m.data->>'domain','')<>''",
		"m.data->'evidence'->'payload'->>'identity_status'='l2_mismatch'",
		"m.data->'evidence'->'payload'->>'claimed_ip'=m.data->>'ip'",
		"lower(coalesce(m.data->'evidence'->'payload'->>'claimed_mac',''))=t.mac",
		"t.observation_id=l.id",
	} {
		if !strings.Contains(selection.CTE, guard) {
			t.Fatalf("SADP display association lost guard %q", guard)
		}
	}
}

func TestIndexedMergedSADPClueKeepsOriginalAttribution(t *testing.T) {
	now := time.Now().UTC()
	confirmed := Observation{ID: "direct", Origin: "sadp", IP: "10.126.253.1", MAC: "08:54:11:13:c1:84", DeviceType: "access_control", Confidence: "strong", ObservedAt: now, ValidUntil: now.Add(time.Minute)}
	clue := Observation{ID: "routed", Origin: "sadp", IP: confirmed.IP, Confidence: "clue", ObservedAt: now.Add(-time.Hour), ValidUntil: now.Add(-time.Minute)}
	clue.Evidence.Payload = map[string]any{"identity_status": "l2_mismatch", "claimed_mac": confirmed.MAC}
	rows := []deviceObservationRow{
		{DeviceKey: "mac-key", IndexedIdentityKey: "scope-mac", Observation: confirmed},
		{DeviceKey: "mac-key", IndexedIdentityKey: "scope-mac", Observation: clue},
	}
	items, err := aggregateIndexedDeviceRows(rows, now)
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	item := items[0]
	if item.DeviceType != "access_control" || item.EvidenceCount != 2 || len(item.Observations) != 2 {
		t.Fatalf("merged device lost type or evidence: %+v", item)
	}
	for _, observation := range item.Observations {
		if observation.ID == "routed" && (observation.MAC != "" || observation.DeviceType != "" || observation.Evidence.Payload["identity_status"] != "l2_mismatch") {
			t.Fatalf("unverified evidence was promoted: %+v", observation)
		}
	}
}
