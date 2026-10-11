package store

import (
	"context"
	"time"
)

// PassiveDiscoveryRecognitionHints returns only current observations that were
// linked to an endpoint through event-time MAC/IP identity. The bounded result
// is consumed by the asynchronous recognition read model, not the ingest path.
func (s *PostgresStore) PassiveDiscoveryRecognitionHints(ctx context.Context, endpointIDs []string, now time.Time) (map[string][]DiscoveryRecognitionHint, error) {
	out := map[string][]DiscoveryRecognitionHint{}
	if len(endpointIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `WITH latest AS (
 SELECT DISTINCT ON (l.endpoint_id,o.origin,lower(o.data->>'name'))
   l.endpoint_id,o.data->>'name' AS value,o.origin,o.id,o.observed_at
 FROM discovery_identity_links l
 JOIN discovery_observations o ON o.id=l.observation_id
 WHERE l.endpoint_id=ANY($1::text[]) AND l.valid_until>$2
   AND o.observed_at<=$2 AND o.valid_until>$2 AND NOT o.withdrawn
   AND o.origin IN ('dns_sd','dhcp') AND coalesce(o.data->>'name','')<>''
 ORDER BY l.endpoint_id,o.origin,lower(o.data->>'name'),o.observed_at DESC,o.id DESC
), ranked AS (
 SELECT *,row_number() OVER(PARTITION BY endpoint_id ORDER BY observed_at DESC,id DESC) AS rank
 FROM latest
)
SELECT endpoint_id,value,origin,id,observed_at FROM ranked WHERE rank<=20 ORDER BY endpoint_id,rank`, endpointIDs, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var endpointID string
		var hint DiscoveryRecognitionHint
		if err = rows.Scan(&endpointID, &hint.Value, &hint.Origin, &hint.ObservationID, &hint.ObservedAt); err != nil {
			return nil, err
		}
		if !usableAutomaticDeviceName(hint.Value, "hostname") {
			continue
		}
		out[endpointID] = append(out[endpointID], hint)
	}
	return out, rows.Err()
}
