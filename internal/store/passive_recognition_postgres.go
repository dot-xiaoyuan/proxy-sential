package store

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// PassiveDiscoveryRecognitionHints returns only current observations that were
// linked to an endpoint through event-time MAC/IP identity. The bounded result
// is consumed by the asynchronous recognition read model, not the ingest path.
//
// Hostnames keep the historical "generic hint" shape. Self-reported protocol
// fields (SSDP model/manufacturer, SNMP model/sysObjectID/sysDescr, DNS-SD
// model) are returned with Field set so the recognition layer can route each
// value to the structured input it belongs to.
func (s *PostgresStore) PassiveDiscoveryRecognitionHints(ctx context.Context, endpointIDs []string, now time.Time) (map[string][]DiscoveryRecognitionHint, error) {
	out := map[string][]DiscoveryRecognitionHint{}
	if len(endpointIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `WITH candidates AS (
 SELECT l.endpoint_id,o.id AS observation_id,o.origin,o.observed_at,''::text AS field,o.data->>'name' AS value
 FROM discovery_identity_links l
 JOIN discovery_observations o ON o.id=l.observation_id
 WHERE l.endpoint_id=ANY($1::text[]) AND l.valid_until>$2
   AND o.observed_at<=$2 AND o.valid_until>$2 AND NOT o.withdrawn
   AND o.origin IN ('dns_sd','dhcp') AND coalesce(o.data->>'name','')<>''
 UNION ALL
 SELECT l.endpoint_id,o.id,o.origin,o.observed_at,f.field,coalesce(o.data->>f.key,'')
 FROM discovery_identity_links l
 JOIN discovery_observations o ON o.id=l.observation_id
 JOIN (VALUES ('ssdp','model_name','ssdp_model'),
              ('ssdp','manufacturer','ssdp_manufacturer'),
              ('snmp','model_name','snmp_model'),
              ('dns_sd','model_name','mdns_model'),
              ('dns_sd','model_name','dns_sd_model')) AS f(origin,key,field)
   ON o.origin=f.origin
 WHERE l.endpoint_id=ANY($1::text[]) AND l.valid_until>$2
   AND o.observed_at<=$2 AND o.valid_until>$2 AND NOT o.withdrawn
   AND coalesce(o.data->>f.key,'')<>''
 UNION ALL
 SELECT l.endpoint_id,o.id,o.origin,o.observed_at,'snmp_sysoid',coalesce(o.data->'evidence'->'payload'->>'system_object_id','')
 FROM discovery_identity_links l
 JOIN discovery_observations o ON o.id=l.observation_id
 WHERE l.endpoint_id=ANY($1::text[]) AND l.valid_until>$2
   AND o.observed_at<=$2 AND o.valid_until>$2 AND NOT o.withdrawn
   AND o.origin='snmp' AND coalesce(o.data->'evidence'->'payload'->>'system_object_id','')<>''
 UNION ALL
 SELECT l.endpoint_id,o.id,o.origin,o.observed_at,'snmp_sysdescr',coalesce(o.data->'evidence'->'payload'->>'system_description','')
 FROM discovery_identity_links l
 JOIN discovery_observations o ON o.id=l.observation_id
 WHERE l.endpoint_id=ANY($1::text[]) AND l.valid_until>$2
   AND o.observed_at<=$2 AND o.valid_until>$2 AND NOT o.withdrawn
   AND o.origin='snmp' AND coalesce(o.data->'evidence'->'payload'->>'system_description','')<>''
), deduped AS (
 SELECT DISTINCT ON (endpoint_id,origin,field,lower(value))
   endpoint_id,observation_id,origin,observed_at,field,value
 FROM candidates
 ORDER BY endpoint_id,origin,field,lower(value),observed_at DESC,observation_id DESC
), ranked AS (
 SELECT *,row_number() OVER(PARTITION BY endpoint_id ORDER BY observed_at DESC,observation_id DESC) AS rank
 FROM deduped
)
SELECT endpoint_id,value,field,origin,observation_id,observed_at FROM ranked WHERE rank<=40 ORDER BY endpoint_id,rank`, endpointIDs, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var endpointID string
		var hint DiscoveryRecognitionHint
		if err = rows.Scan(&endpointID, &hint.Value, &hint.Field, &hint.Origin, &hint.ObservationID, &hint.ObservedAt); err != nil {
			return nil, err
		}
		hint.Value = strings.TrimSpace(hint.Value)
		if hint.Field == "" {
			if !usableAutomaticDeviceName(hint.Value, "hostname") {
				continue
			}
		} else if !usableRecognitionFieldValue(hint.Field, hint.Value) {
			continue
		}
		out[endpointID] = append(out[endpointID], hint)
	}
	return out, rows.Err()
}

// usableRecognitionFieldValue bounds self-reported protocol values before they
// become recognition inputs. Over-long values are dropped rather than
// truncated: a partial model code or OID is worse than no hint.
func usableRecognitionFieldValue(field, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	limit := 128
	if field == "snmp_sysdescr" {
		limit = 512
	}
	return utf8.RuneCountInString(value) <= limit
}
