package store

import (
	"context"
	"strings"
	"time"

	"proxy-sentinel/internal/streamidentity"
)

// StreamDiscoveryRecognitionHints reads current compact facts for a small set
// of affected endpoints. It never scans the event archive or all device facts.
func (s *PostgresStore) StreamDiscoveryRecognitionHints(ctx context.Context, endpointIDs []string, now time.Time) (map[string][]DiscoveryRecognitionHint, error) {
	out := map[string][]DiscoveryRecognitionHint{}
	if len(endpointIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, streamRecognitionHintsSQL, endpointIDs, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var hint DiscoveryRecognitionHint
		if err = rows.Scan(&id, &hint.Value, &hint.Field, &hint.Origin, &hint.ObservationID, &hint.ObservedAt, &hint.ValidUntil, &hint.Association); err != nil {
			return nil, err
		}
		hint.Value = strings.TrimSpace(hint.Value)
		if !usableRecognitionFieldValue(hint.Field, hint.Value) {
			continue
		}
		out[id] = append(out[id], hint)
	}
	return out, rows.Err()
}

// Two indexed candidate paths: direct protocol MAC and at most 16 current
// address bindings. IP-only product facts must then pass the same unique,
// physical-scope and event-time ownership check as the diagnostic observer.
// Saturated binding sets fail closed; no old event body or lease is scanned.
const streamRecognitionHintsSQL = `WITH candidates AS (
 SELECT e.endpoint_id,f.protocol,f.visible_event_key,f.observed_at,f.valid_until,f.recognition_fields,f.association_quality
 FROM endpoint_entities e
 JOIN LATERAL (
  WITH source_candidates AS MATERIALIZED (
   (SELECT f.protocol,f.mac,f.ip,f.sensor_id,f.site,f.domain,f.vlan,f.vrf,f.interface_name,
     f.observed_at,f.valid_until,f.visible_event_key,f.recognition_fields FROM stream_discovery_facts f
    JOIN stream_source_cutovers c ON c.epoch=f.epoch AND c.state='active'
    WHERE lower(f.mac)=e.primary_mac AND f.mac<>''
     AND NOT f.withdrawn AND f.observed_at<=$2 AND f.valid_until>$2
     AND f.recognition_fields<>'{}'::jsonb
    ORDER BY f.observed_at DESC,f.visible_event_key DESC LIMIT 40)
   UNION
   (SELECT f.* FROM (
     SELECT limited.*,count(*) OVER() AS binding_count FROM (
      SELECT b.ip,b.sensor_id,b.site,b.domain,b.vlan,b.vrf,b.interface_name FROM stream_discovery_facts b
      JOIN stream_source_cutovers c ON c.epoch=b.epoch AND c.state='active'
      WHERE lower(b.mac)=e.primary_mac AND b.mac<>'' AND b.address_binding
       AND b.protocol IN ('dhcp','dhcpv6','arp','ndp') AND NOT b.withdrawn
       AND b.observed_at<=$2 AND b.valid_until>$2
      ORDER BY b.observed_at DESC,b.event_key DESC LIMIT 17
     ) limited
    ) b
    JOIN stream_source_cutovers c ON c.state='active'
    JOIN LATERAL (
     SELECT f.protocol,f.mac,f.ip,f.sensor_id,f.site,f.domain,f.vlan,f.vrf,f.interface_name,
     f.observed_at,f.valid_until,f.visible_event_key,f.recognition_fields FROM stream_discovery_facts f
     WHERE b.binding_count<=16 AND f.epoch=c.epoch AND f.ip=b.ip AND f.ip<>'' AND f.mac=''
      AND f.sensor_id=b.sensor_id AND f.site=b.site AND f.domain=b.domain
      AND f.vlan=b.vlan AND f.vrf=b.vrf AND f.interface_name=b.interface_name
      AND NOT f.withdrawn AND f.observed_at<=$2 AND f.valid_until>$2
      AND f.recognition_fields<>'{}'::jsonb
     ORDER BY f.observed_at DESC,f.visible_event_key DESC LIMIT 40
    ) f ON true
    ORDER BY f.observed_at DESC,f.visible_event_key DESC LIMIT 40)
  )
  SELECT f.protocol,f.visible_event_key,f.observed_at,f.valid_until,f.recognition_fields,
   CASE WHEN f.protocol IN ('dhcp','dhcpv6') OR f.ip='' THEN 'direct' ELSE 'unique_stream_binding' END AS association_quality
  FROM source_candidates f
  CROSS JOIN LATERAL (SELECT ` + streamidentity.FactContextSQL + ` AS association) v
  ` + streamidentity.MACLateralSQL + `
  WHERE identity.mac=e.primary_mac
  ORDER BY f.observed_at DESC,f.visible_event_key DESC LIMIT 40
 ) f ON true
 WHERE e.endpoint_id=ANY($1::text[]) AND e.entity_role='endpoint'
), ranked AS (
 SELECT c.endpoint_id,c.protocol,c.visible_event_key,c.observed_at,c.valid_until,c.association_quality,kv.key AS field,kv.value,
        row_number() OVER(PARTITION BY c.endpoint_id ORDER BY c.observed_at DESC,c.visible_event_key DESC,kv.key) AS rank
 FROM candidates c CROSS JOIN LATERAL jsonb_each_text(c.recognition_fields) kv
)
SELECT endpoint_id,value,field,protocol,visible_event_key,observed_at,valid_until,association_quality
FROM ranked WHERE rank<=40 ORDER BY endpoint_id,rank`
