package store

import (
	"context"
	"database/sql"
	"encoding/json"
)

// DHCP ownership is scoped by sensor and campus. A later release/reassignment
// invalidates the older lease. Current account sessions are an independent
// address source; neither source creates or merges endpoint identities.
const deviceCenterAddressCTE = `WITH latest_leases AS MATERIALIZED (
 SELECT l.sensor_id,l.campus_id,l.ip,l.endpoint_id,l.action,l.valid_until
 FROM device_address_leases l WHERE l.action='ack' AND l.valid_until>now() AND l.observed_at<=now()
 AND NOT EXISTS(SELECT 1 FROM device_address_leases newer WHERE newer.sensor_id=l.sensor_id AND newer.campus_id=l.campus_id AND newer.ip=l.ip AND newer.observed_at<=now() AND (newer.observed_at,newer.event_id)>(l.observed_at,l.event_id))
), current_addresses AS MATERIALIZED (
 SELECT endpoint_id,array_agg(host(ip) ORDER BY family(ip),ip) addresses FROM (
 SELECT endpoint_id,ip FROM latest_leases WHERE action='ack' AND valid_until>now()
 UNION SELECT endpoint_id,ip FROM account_sessions WHERE endpoint_id IS NOT NULL AND endpoint_id<>'' AND ip IS NOT NULL AND started_at<=now() AND ended_at IS NULL AND updated_at>=now()-interval '90 minutes'
 UNION SELECT document->>'endpoint_id',(document->>'ip')::inet FROM account_identity_session_projection p JOIN account_identity_projection_sources src USING(source,sensor_id,campus_id,access_domain) WHERE coalesce(document->>'ended_at','')='' AND coalesce(document->>'endpoint_id','')<>'' AND coalesce(document->>'ip','')<>'' AND p.confirmed_at<=now() AND p.confirmed_at>=now()-interval '90 minutes' AND src.observed_at>=now()-make_interval(secs=>GREATEST(60,LEAST(86400,COALESCE(NULLIF(document->>'reconcile_interval_seconds','')::int,1800)))*3)
 ) addresses GROUP BY endpoint_id
) `

func ReadCurrentEndpointAddresses(ctx context.Context, db *sql.DB, id string) ([]string, error) {
	var b []byte
	err := db.QueryRowContext(ctx, deviceCenterAddressCTE+`SELECT coalesce((SELECT to_jsonb(addresses) FROM current_addresses WHERE endpoint_id=$1),'[]'::jsonb)`, id).Scan(&b)
	if err != nil {
		return nil, err
	}
	addresses := []string{}
	err = json.Unmarshal(b, &addresses)
	return addresses, err
}
