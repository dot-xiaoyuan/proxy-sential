package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"proxy-sentinel/internal/normalized"
)

type discoveryFactVersion struct {
	Event    string
	Revision int64
	Observed time.Time
	Hash     string
}

func (v discoveryFactVersion) supersededBy(next discoveryFactVersion) bool {
	if v.Event == next.Event {
		return next.Revision > v.Revision
	}
	return next.Observed.After(v.Observed) || (next.Observed.Equal(v.Observed) && next.Event > v.Event)
}

// Device locks are held by the caller. Read each distinct fact once, then
// decide all events in segment order before publishing the winning facts.
func loadDiscoveryFactVersions(ctx context.Context, tx *sql.Tx, events []normalized.Event) (map[string]discoveryFactVersion, error) {
	type keyRow struct {
		Device string `json:"device_key"`
		Fact   string `json:"fact_key"`
	}
	input := make([]keyRow, 0, len(events))
	seen := make(map[string]bool, len(events))
	for _, event := range events {
		adapted, err := AdaptDiscoveryEvent(event)
		if err != nil {
			continue
		}
		observation, err := FromEvent(adapted)
		if err != nil || (observation.IP != "" && !IsPrivateDiscoveryAddress(observation.IP)) {
			continue
		}
		device, fact := discoveryStateKey(observation), discoveryFactKey(observation)
		identity := device + "\x00" + fact
		if !seen[identity] {
			seen[identity] = true
			input = append(input, keyRow{device, fact})
		}
	}
	result := make(map[string]discoveryFactVersion, len(input))
	if len(input) == 0 {
		return result, nil
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT v.device_key,v.fact_key,f.event_id,f.revision,f.observed_at,f.content_hash
 FROM jsonb_to_recordset($1::jsonb) AS v(device_key text,fact_key text)
 JOIN LATERAL (
   SELECT event_id,revision,observed_at,content_hash
   FROM discovery_service_facts_v2 f
   WHERE f.device_key=v.device_key AND f.fact_key=v.fact_key
   LIMIT 1
 ) f ON true`, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var device, fact string
		var version discoveryFactVersion
		if err = rows.Scan(&device, &fact, &version.Event, &version.Revision, &version.Observed, &version.Hash); err != nil {
			return nil, err
		}
		result[device+"\x00"+fact] = version
	}
	return result, rows.Err()
}

type discoveryFactWrite struct {
	Device          string          `json:"device_key"`
	Fact            string          `json:"fact_key"`
	Sensor          string          `json:"sensor_id"`
	Domain          string          `json:"domain"`
	VLAN            string          `json:"vlan"`
	Interface       string          `json:"interface_name"`
	Source          string          `json:"source_id"`
	Protocol        string          `json:"protocol"`
	ServiceInstance string          `json:"service_instance"`
	IP              string          `json:"ip"`
	MAC             string          `json:"mac"`
	Event           string          `json:"event_id"`
	Revision        int64           `json:"revision"`
	Observed        time.Time       `json:"observed_at"`
	ValidUntil      time.Time       `json:"valid_until"`
	Withdrawn       bool            `json:"withdrawn"`
	Observation     json.RawMessage `json:"observation"`
	Hash            string          `json:"content_hash"`
}

func insertDiscoveryFacts(ctx context.Context, tx *sql.Tx, facts map[string]discoveryFactWrite) error {
	if len(facts) == 0 {
		return nil
	}
	input := make([]discoveryFactWrite, 0, len(facts))
	for _, fact := range facts {
		input = append(input, fact)
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO discovery_service_facts_v2(device_key,fact_key,sensor_id,domain,vlan,interface_name,source_id,protocol,service_instance,ip,mac,event_id,revision,observed_at,valid_until,withdrawn,observation,content_hash)
 SELECT v.device_key,v.fact_key,v.sensor_id,v.domain,v.vlan,v.interface_name,v.source_id,v.protocol,v.service_instance,v.ip,v.mac,v.event_id,v.revision,v.observed_at,v.valid_until,v.withdrawn,v.observation,v.content_hash
 FROM jsonb_to_recordset($1::jsonb) AS v(device_key text,fact_key text,sensor_id text,domain text,vlan text,interface_name text,source_id text,protocol text,service_instance text,ip text,mac text,event_id text,revision bigint,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,observation jsonb,content_hash text)
 WHERE true
 ON CONFLICT(device_key,fact_key) DO UPDATE SET event_id=EXCLUDED.event_id,revision=EXCLUDED.revision,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,observation=EXCLUDED.observation,content_hash=EXCLUDED.content_hash
 WHERE (EXCLUDED.event_id=discovery_service_facts_v2.event_id AND EXCLUDED.revision>discovery_service_facts_v2.revision)
 OR (EXCLUDED.event_id<>discovery_service_facts_v2.event_id AND (EXCLUDED.observed_at,EXCLUDED.event_id)>(discovery_service_facts_v2.observed_at,discovery_service_facts_v2.event_id))`, raw)
	return err
}
