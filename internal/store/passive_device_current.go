package store

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
)

func touchPassiveLatest(ctx context.Context, db passiveDiscoveryDB, rows []map[string]any) error {
	if len(rows) == 0 {
		return nil
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE discovery_observation_latest l
SET observed_at=r.observed_at,
    valid_until=CASE WHEN r.valid_until<l.valid_until THEN r.valid_until ELSE GREATEST(l.valid_until, r.valid_until) END
FROM jsonb_to_recordset($1::jsonb) AS r(id text, observed_at timestamptz, valid_until timestamptz)
WHERE l.id=r.id AND r.observed_at>=l.observed_at
 AND (r.observed_at>=l.observed_at+interval '60 seconds' OR r.valid_until<l.valid_until)`, string(payload))
	return err
}

func passiveListIdentityKey(o discovery.Observation, endpointID string) string {
	mac := strings.ToLower(o.MAC)
	endpoint := strings.ToLower(endpointID)
	unicast := func(value string) bool {
		parsed, err := net.ParseMAC(value)
		return err == nil && len(parsed) == 6 && parsed[0]&1 == 0 && parsed.String() != "00:00:00:00:00:00"
	}
	var raw []byte
	switch {
	case strings.HasPrefix(endpoint, "mac:") && unicast(strings.TrimPrefix(endpoint, "mac:")) && (mac == "" || endpoint == "mac:"+mac):
		raw, _ = json.Marshal([]any{"identity", o.Node, o.Site, o.Domain, o.VLAN, o.VRF, "mac", strings.TrimPrefix(endpoint, "mac:")})
	case endpoint != "":
		raw, _ = json.Marshal([]any{"identity", o.Node, o.Site, o.Domain, o.VLAN, o.VRF, "endpoint", endpoint})
	case unicast(mac):
		raw, _ = json.Marshal([]any{"identity", o.Node, o.Site, o.Domain, o.VLAN, o.VRF, "mac", mac})
	default:
		raw, _ = json.Marshal([]any{"discovery_key", o.Key()})
	}
	return string(raw)
}

func passiveDeviceCategory(deviceType string) string {
	deviceType = strings.ToLower(strings.TrimSpace(deviceType))
	if deviceType == "" {
		return "identity_only"
	}
	for _, kind := range discovery.DeviceTypes {
		if kind.ID == deviceType {
			return kind.Category
		}
	}
	return "identity_only"
}

func upsertPassiveDeviceCurrent(ctx context.Context, db passiveDiscoveryDB, pending map[string]discovery.Observation) error {
	if len(pending) == 0 {
		return nil
	}
	rows := make([]map[string]any, 0, len(pending))
	index := map[string]int{}
	for _, o := range pending {
		mac := strings.ToLower(o.MAC)
		random := false
		if parsed, err := net.ParseMAC(mac); err == nil && len(parsed) == 6 {
			random = parsed[0]&2 != 0
		}
		types := []string{}
		if o.DeviceType != "" {
			types = []string{o.DeviceType}
		}
		key := passiveListIdentityKey(o, "")
		row := map[string]any{
			"identity_key": key,
			"device_key":   o.Key(),
			"mac":          mac,
			"ip":           o.IP,
			"name":         o.Name,
			"device_type":  o.DeviceType,
			"last_seen":    o.ObservedAt,
			"valid_until":  o.ValidUntil,
			"domain":       o.Domain,
			"vlan":         o.VLAN,
			"origin":       o.Origin,
			"os_family":    o.OSHint,
			"category":     passiveDeviceCategory(o.DeviceType),
			"random_mac":   random,
			"search_text":  strings.ToLower(strings.Join([]string{o.Name, mac, o.IP, o.Manufacturer, o.ModelName, o.DeviceType}, " ")),
			"types":        types,
			"capabilities": o.Capabilities,
		}
		// One statement cannot update the same identity twice. Several facts
		// share a MAC; keep the newest observation from this batch.
		if at, exists := index[key]; exists {
			if previous, ok := rows[at]["last_seen"].(time.Time); !ok || !o.ObservedAt.Before(previous) {
				rows[at] = row
			}
			continue
		}
		index[key] = len(rows)
		rows = append(rows, row)
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO discovery_passive_device_current(
 identity_key,device_key,device_keys,mac,ip,name,device_type,last_seen,valid_until,domain,vlan,origins,capabilities,random_mac,search_text,os_family,category,effective_types)
SELECT identity_key,device_key,ARRAY[device_key],mac,ip,name,device_type,last_seen,valid_until,domain,vlan,ARRAY[origin],coalesce(capabilities,'{}'::text[]),random_mac,search_text,os_family,category,coalesce(types,'{}'::text[])
FROM jsonb_to_recordset($1::jsonb) AS r(
 identity_key text,device_key text,mac text,ip text,name text,device_type text,last_seen timestamptz,valid_until timestamptz,
 domain text,vlan text,origin text,os_family text,category text,random_mac boolean,search_text text,types text[],capabilities text[])
ORDER BY identity_key
ON CONFLICT(identity_key) DO UPDATE SET
 device_key=CASE WHEN EXCLUDED.last_seen>=discovery_passive_device_current.last_seen THEN EXCLUDED.device_key ELSE discovery_passive_device_current.device_key END,
 device_keys=(SELECT ARRAY(SELECT DISTINCT key FROM unnest(discovery_passive_device_current.device_keys || EXCLUDED.device_keys) key)),
 mac=CASE WHEN EXCLUDED.last_seen>=discovery_passive_device_current.last_seen THEN EXCLUDED.mac ELSE discovery_passive_device_current.mac END,
 ip=CASE WHEN EXCLUDED.last_seen>=discovery_passive_device_current.last_seen THEN EXCLUDED.ip ELSE discovery_passive_device_current.ip END,
 name=CASE WHEN EXCLUDED.last_seen>=discovery_passive_device_current.last_seen AND EXCLUDED.name<>'' THEN EXCLUDED.name ELSE discovery_passive_device_current.name END,
 device_type=CASE WHEN EXCLUDED.last_seen>=discovery_passive_device_current.last_seen AND EXCLUDED.device_type<>'' THEN EXCLUDED.device_type ELSE discovery_passive_device_current.device_type END,
 last_seen=GREATEST(discovery_passive_device_current.last_seen, EXCLUDED.last_seen),
 valid_until=CASE WHEN EXCLUDED.valid_until<discovery_passive_device_current.valid_until THEN EXCLUDED.valid_until ELSE GREATEST(discovery_passive_device_current.valid_until, EXCLUDED.valid_until) END,
 domain=CASE WHEN EXCLUDED.domain<>'' THEN EXCLUDED.domain ELSE discovery_passive_device_current.domain END,
 vlan=CASE WHEN EXCLUDED.vlan<>'' THEN EXCLUDED.vlan ELSE discovery_passive_device_current.vlan END,
 origins=(SELECT ARRAY(SELECT DISTINCT origin FROM unnest(discovery_passive_device_current.origins || EXCLUDED.origins) origin)),
 capabilities=(SELECT ARRAY(SELECT DISTINCT cap FROM unnest(discovery_passive_device_current.capabilities || EXCLUDED.capabilities) cap)),
 random_mac=discovery_passive_device_current.random_mac OR EXCLUDED.random_mac,
 search_text=CASE WHEN EXCLUDED.last_seen>=discovery_passive_device_current.last_seen THEN EXCLUDED.search_text ELSE discovery_passive_device_current.search_text END,
 os_family=CASE WHEN EXCLUDED.os_family<>'' THEN EXCLUDED.os_family ELSE discovery_passive_device_current.os_family END,
 category=CASE WHEN EXCLUDED.category<>'identity_only' THEN EXCLUDED.category ELSE discovery_passive_device_current.category END,
 effective_types=CASE WHEN cardinality(EXCLUDED.effective_types)>0 THEN EXCLUDED.effective_types ELSE discovery_passive_device_current.effective_types END,
 updated_at=now()
WHERE discovery_passive_device_current.device_type IS DISTINCT FROM EXCLUDED.device_type
 OR discovery_passive_device_current.name IS DISTINCT FROM EXCLUDED.name
 OR NOT (EXCLUDED.device_keys <@ discovery_passive_device_current.device_keys)
 OR EXCLUDED.valid_until<discovery_passive_device_current.valid_until`, string(payload))
	return err
}

// adoptPassiveDeviceCurrent copies a bounded slice of the current latest
// projection into the device table. It does not replay historical events.
func (s *DBStore) adoptPassiveDeviceCurrent(ctx context.Context) error {
	jobCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	_, err := s.pg.db.ExecContext(jobCtx, `WITH picked AS (
 SELECT CASE WHEN coalesce(data->>'mac','')<>'' THEN jsonb_build_array('identity',coalesce(data->>'node',''),coalesce(data->>'site',''),coalesce(data->>'domain',''),coalesce(data->>'vlan',''),coalesce(data->>'vrf',''),'mac',lower(data->>'mac'))::text
  ELSE jsonb_build_array('discovery_key',device_key)::text END AS identity_key,
  device_key, lower(coalesce(data->>'mac','')) AS mac, coalesce(data->>'ip','') AS ip, coalesce(data->>'name','') AS name, coalesce(data->>'device_type','') AS device_type,
  observed_at, valid_until, coalesce(data->>'domain','') AS domain, coalesce(data->>'vlan','') AS vlan, origin,
  coalesce(ARRAY(SELECT jsonb_array_elements_text(coalesce(data->'capabilities','[]'::jsonb))), '{}'::text[]) AS capabilities,
  CASE WHEN coalesce(data->>'mac','') ~ '^[0-9a-fA-F]{2}' THEN ((('x'||substr(data->>'mac',1,2))::bit(8)::int) & 2)=2 ELSE false END AS random_mac,
  lower(concat_ws(' ', data->>'name', data->>'mac', data->>'ip', data->>'manufacturer', data->>'model_name', data->>'device_type')) AS search_text,
  coalesce(data->>'os_hint','') AS os_family,
  CASE lower(coalesce(data->>'device_type',''))
   WHEN 'mobile' THEN 'mobile' WHEN 'phone' THEN 'mobile' WHEN 'smartphone' THEN 'mobile'
   WHEN 'tablet' THEN 'tablet' WHEN 'desktop' THEN 'desktop' WHEN 'computer' THEN 'desktop' WHEN 'laptop' THEN 'desktop'
   WHEN 'printer' THEN 'printer' WHEN 'camera' THEN 'camera' WHEN 'media_device' THEN 'media'
   WHEN 'router' THEN 'network' WHEN 'switch' THEN 'network' WHEN 'access_point' THEN 'network' WHEN 'gateway' THEN 'network'
   WHEN '' THEN 'identity_only' ELSE 'identity_only' END AS category,
  CASE WHEN coalesce(data->>'device_type','')<>'' THEN ARRAY[data->>'device_type'] ELSE '{}'::text[] END AS effective_types
 FROM discovery_observation_latest l
 WHERE l.observed_at>now()-interval '30 days'
  AND NOT EXISTS (SELECT 1 FROM discovery_passive_device_current c WHERE l.device_key=ANY(c.device_keys))
 ORDER BY l.observed_at DESC
 LIMIT 2000
), unique_rows AS (
 SELECT DISTINCT ON (identity_key) * FROM picked ORDER BY identity_key, observed_at DESC
)
INSERT INTO discovery_passive_device_current(
 identity_key,device_key,device_keys,mac,ip,name,device_type,last_seen,valid_until,domain,vlan,origins,capabilities,random_mac,search_text,os_family,category,effective_types)
SELECT identity_key,device_key,ARRAY[device_key],mac,ip,name,device_type,observed_at,valid_until,domain,vlan,ARRAY[origin],capabilities,random_mac,search_text,os_family,category,effective_types
FROM unique_rows
ON CONFLICT(identity_key) DO UPDATE SET
 device_keys=(SELECT ARRAY(SELECT DISTINCT key FROM unnest(discovery_passive_device_current.device_keys || EXCLUDED.device_keys) key)),
 last_seen=GREATEST(discovery_passive_device_current.last_seen, EXCLUDED.last_seen),
 origins=(SELECT ARRAY(SELECT DISTINCT origin FROM unnest(discovery_passive_device_current.origins || EXCLUDED.origins) origin))
WHERE EXCLUDED.last_seen>discovery_passive_device_current.last_seen`)
	return err
}
