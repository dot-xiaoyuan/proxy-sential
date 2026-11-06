package store

import (
	"context"
	"encoding/json"
	"time"

	"proxy-sentinel/internal/discovery"
)

type passiveARPBatchRow struct {
	ID         string          `json:"id"`
	DeviceKey  string          `json:"device_key"`
	SourceID   string          `json:"source_id"`
	ObservedAt time.Time       `json:"observed_at"`
	ValidUntil time.Time       `json:"valid_until"`
	Data       json.RawMessage `json:"data"`
	EndpointID string          `json:"endpoint_id"`
	Basis      json.RawMessage `json:"basis"`
}

// ARP sender observations have an unambiguous frame-level MAC. The candidate
// endpoint upsert runs before this statement; the join still checks that the
// endpoint exists with the endpoint role. One bounded statement preserves the
// per-event observation and link triggers without one round trip per row.
func (s *DBStore) insertPassiveARPBatch(ctx context.Context, db passiveDiscoveryDB, observations []discovery.Observation) error {
	if len(observations) == 0 {
		return nil
	}
	rows := make([]passiveARPBatchRow, 0, len(observations))
	for _, o := range observations {
		data, err := json.Marshal(o)
		if err != nil {
			return err
		}
		basis, err := json.Marshal(map[string]any{"kind": "passive_arp_sender_identity", "sensor": o.Node, "ip": o.IP, "mac": o.MAC, "origin": o.Origin})
		if err != nil {
			return err
		}
		rows = append(rows, passiveARPBatchRow{ID: o.ID, DeviceKey: o.Key(), SourceID: o.SourceID, ObservedAt: o.ObservedAt, ValidUntil: o.ValidUntil, Data: data, EndpointID: "mac:" + o.MAC, Basis: basis})
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `WITH incoming AS (
 SELECT * FROM jsonb_to_recordset($1::jsonb) AS r(id text,device_key text,source_id text,observed_at timestamptz,valid_until timestamptz,data jsonb,endpoint_id text,basis jsonb)
), stored AS (
 INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data)
 SELECT id,device_key,source_id,'arp',observed_at,valid_until,false,data FROM incoming ORDER BY id
 ON CONFLICT(id) DO UPDATE SET device_key=EXCLUDED.device_key,source_id=EXCLUDED.source_id,origin=EXCLUDED.origin,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,data=EXCLUDED.data
 WHERE EXCLUDED.observed_at>=discovery_observations.observed_at
 RETURNING id
)
INSERT INTO discovery_identity_links(observation_id,endpoint_id,valid_until,basis)
SELECT i.id,i.endpoint_id,i.valid_until,i.basis FROM incoming i JOIN stored s USING(id)
JOIN endpoint_entities e ON e.endpoint_id=i.endpoint_id AND e.entity_role='endpoint'
ORDER BY i.endpoint_id,i.id
ON CONFLICT(observation_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id,valid_until=EXCLUDED.valid_until,basis=EXCLUDED.basis
WHERE discovery_identity_links.endpoint_id IS DISTINCT FROM EXCLUDED.endpoint_id OR discovery_identity_links.basis IS DISTINCT FROM EXCLUDED.basis OR EXCLUDED.valid_until>discovery_identity_links.valid_until+interval '5 minutes'`, string(raw))
	return err
}
