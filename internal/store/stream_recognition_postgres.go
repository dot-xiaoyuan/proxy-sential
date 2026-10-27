package store

import (
	"context"
	"strings"
	"time"
)

// StreamDiscoveryRecognitionHints reads current compact facts for a small set
// of affected endpoints. It never scans the event archive or all device facts.
func (s *PostgresStore) StreamDiscoveryRecognitionHints(ctx context.Context, endpointIDs []string, now time.Time) (map[string][]DiscoveryRecognitionHint, error) {
	out := map[string][]DiscoveryRecognitionHint{}
	if len(endpointIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `WITH candidates AS (
 SELECT e.endpoint_id,f.protocol,f.visible_event_key,f.observed_at,f.recognition_fields
 FROM endpoint_entities e
 JOIN LATERAL (
  SELECT f.protocol,f.visible_event_key,f.observed_at,f.recognition_fields
  FROM stream_discovery_facts f
  JOIN stream_source_cutovers c ON c.epoch=f.epoch AND c.state='active'
  WHERE lower(f.mac)=lower(e.primary_mac) AND f.mac<>''
    AND NOT f.withdrawn AND f.observed_at<=$2 AND f.valid_until>$2
    AND f.recognition_fields<>'{}'::jsonb
    AND (f.ip='' OR EXISTS (
      SELECT 1 FROM device_address_leases l
      WHERE l.sensor_id=f.sensor_id AND l.campus_id=f.site AND l.ip=f.ip::inet
        AND l.action='ack' AND l.endpoint_id=e.endpoint_id
        AND l.observed_at<=f.observed_at AND l.valid_until>f.observed_at
    ))
  ORDER BY f.observed_at DESC,f.visible_event_key DESC LIMIT 40
 ) f ON true
 WHERE e.endpoint_id=ANY($1::text[]) AND e.entity_role='endpoint'
), ranked AS (
 SELECT c.endpoint_id,c.protocol,c.visible_event_key,c.observed_at,kv.key AS field,kv.value,
        row_number() OVER(PARTITION BY c.endpoint_id ORDER BY c.observed_at DESC,c.visible_event_key DESC,kv.key) AS rank
 FROM candidates c CROSS JOIN LATERAL jsonb_each_text(c.recognition_fields) kv
)
SELECT endpoint_id,value,field,protocol,visible_event_key,observed_at
FROM ranked WHERE rank<=40 ORDER BY endpoint_id,rank`, endpointIDs, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var hint DiscoveryRecognitionHint
		if err = rows.Scan(&id, &hint.Value, &hint.Field, &hint.Origin, &hint.ObservationID, &hint.ObservedAt); err != nil {
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
