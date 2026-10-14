package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strconv"
	"time"
)

// Batched writes for the identity path.
//
// Every function here replaces a per-item ExecContext loop with one multi-row statement.
// The field measured the cost of the old shape directly: the identity materializer spends
// several statements per event (identity_ip_mac_history, endpoint_entities, policy
// observations, device signal facts, device leases, endpoint device profiles) and died on
// the write side at ~1% of the arrival rate, with a single INSERT into the 9.4 GB
// identity_ip_mac_history taking twelve seconds while other statements waited on row
// locks. Progress notes for the batches keep the statements proportional to the number of
// tables, not to the number of events.
//
// Rules that keep the batches safe:
//   - an empty slice issues no statement at all;
//   - rows are sorted by their conflict key before the arrays are built, so concurrent
//     writers acquire row locks in a deterministic order;
//   - jsonb columns are passed as text arrays and cast per element, which keeps the
//     parameter types independent of the driver's jsonb array encoding.

// jsonText renders a value as JSON text for a text[] parameter that is cast to jsonb.
func jsonText(value any) string {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 {
		return "null"
	}
	return string(raw)
}

// insertIPMACHistoryBatch inserts binding windows. The conflict update keeps the existing
// first_seen and only extends the window, which is what the per-row upsert did.
func insertIPMACHistoryBatch(ctx context.Context, tx *sql.Tx, items []IdentityIPMACHistory) error {
	if len(items) == 0 {
		return nil
	}
	items = append([]IdentityIPMACHistory(nil), items...)
	sort.SliceStable(items, func(i, j int) bool { return items[i].EventID < items[j].EventID })

	eventID := make([]string, len(items))
	endpointID := make([]string, len(items))
	accountID := make([]string, len(items))
	entityRole := make([]string, len(items))
	ip := make([]string, len(items))
	mac := make([]string, len(items))
	source := make([]string, len(items))
	firstSeen := make([]time.Time, len(items))
	lastSeen := make([]time.Time, len(items))
	confidence := make([]float64, len(items))
	sample := make([]string, len(items))
	for index, item := range items {
		eventID[index], endpointID[index], accountID[index] = item.EventID, item.EndpointID, item.AccountID
		entityRole[index], ip[index], mac[index], source[index] = item.EntityRole, item.IP, item.MAC, item.Source
		firstSeen[index], lastSeen[index] = identitySQLTime(item.FirstSeen), identitySQLTime(item.LastSeen)
		confidence[index], sample[index] = item.IdentityConfidence, jsonText(item.EventIDsSample)
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO identity_ip_mac_history(event_id, endpoint_id, account_id, entity_role, ip, mac, source, first_seen, last_seen, identity_confidence, event_ids_sample)
SELECT t.event_id, t.endpoint_id, t.account_id, t.entity_role, NULLIF(t.ip, '')::inet, t.mac, t.source, t.first_seen, t.last_seen, t.confidence, NULLIF(t.sample, '')::jsonb
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::timestamptz[], $9::timestamptz[], $10::float8[], $11::text[])
  AS t(event_id, endpoint_id, account_id, entity_role, ip, mac, source, first_seen, last_seen, confidence, sample)
ON CONFLICT(event_id) DO UPDATE SET
  endpoint_id = EXCLUDED.endpoint_id,
  account_id = EXCLUDED.account_id,
  entity_role = EXCLUDED.entity_role,
  ip = EXCLUDED.ip,
  mac = EXCLUDED.mac,
  source = EXCLUDED.source,
  last_seen = GREATEST(identity_ip_mac_history.last_seen, EXCLUDED.last_seen),
  identity_confidence = GREATEST(identity_ip_mac_history.identity_confidence, EXCLUDED.identity_confidence),
  event_ids_sample = EXCLUDED.event_ids_sample`,
		eventID, endpointID, accountID, entityRole, ip, mac, source, firstSeen, lastSeen, confidence, sample)
	return err
}

// extendIPMACHistoryWindows advances last_seen for binding windows that are already stored.
func extendIPMACHistoryWindows(ctx context.Context, tx *sql.Tx, eventID []string, lastSeen []time.Time) error {
	if len(eventID) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
UPDATE identity_ip_mac_history h
SET last_seen = GREATEST(h.last_seen, v.last_seen)
FROM (SELECT * FROM unnest($1::text[], $2::timestamptz[]) AS t(event_id, last_seen)) v
WHERE h.event_id = v.event_id AND h.last_seen < v.last_seen`,
		eventID, lastSeen)
	return err
}

func insertAccessHistoryBatch(ctx context.Context, tx *sql.Tx, items []IdentityAccessHistory) error {
	if len(items) == 0 {
		return nil
	}
	items = append([]IdentityAccessHistory(nil), items...)
	sort.SliceStable(items, func(i, j int) bool { return items[i].EventID < items[j].EventID })

	eventID := make([]string, len(items))
	endpointID := make([]string, len(items))
	accountID := make([]string, len(items))
	entityRole := make([]string, len(items))
	accessID := make([]string, len(items))
	accessType := make([]string, len(items))
	ap := make([]string, len(items))
	switchID := make([]string, len(items))
	switchPort := make([]string, len(items))
	vlan := make([]string, len(items))
	campusID := make([]string, len(items))
	buildingID := make([]string, len(items))
	networkZoneID := make([]string, len(items))
	ssid := make([]string, len(items))
	nasIP := make([]string, len(items))
	source := make([]string, len(items))
	firstSeen := make([]time.Time, len(items))
	lastSeen := make([]time.Time, len(items))
	confidence := make([]float64, len(items))
	sample := make([]string, len(items))
	for index, item := range items {
		eventID[index], endpointID[index], accountID[index], entityRole[index] = item.EventID, item.EndpointID, item.AccountID, item.EntityRole
		accessID[index], accessType[index], ap[index], switchID[index], switchPort[index] = item.AccessID, item.AccessType, item.AP, item.SwitchID, item.SwitchPort
		vlan[index], campusID[index], buildingID[index], networkZoneID[index], ssid[index], nasIP[index] = item.VLAN, item.CampusID, item.BuildingID, item.NetworkZoneID, item.SSID, item.NASIP
		source[index] = item.Source
		firstSeen[index], lastSeen[index] = identitySQLTime(item.FirstSeen), identitySQLTime(item.LastSeen)
		confidence[index], sample[index] = item.IdentityConfidence, jsonText(item.EventIDsSample)
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO identity_access_history(event_id, endpoint_id, account_id, entity_role, access_id, access_type, ap, switch_id, switch_port, vlan, source, first_seen, last_seen, identity_confidence, event_ids_sample, campus_id, building_id, network_zone_id, ssid, nas_ip)
SELECT t.event_id, t.endpoint_id, t.account_id, t.entity_role, t.access_id, NULLIF(t.access_type,''), NULLIF(t.ap,''), NULLIF(t.switch_id,''), NULLIF(t.switch_port,''), NULLIF(t.vlan,''), t.source, t.first_seen, t.last_seen, t.confidence, NULLIF(t.sample,'')::jsonb, NULLIF(t.campus_id,''), NULLIF(t.building_id,''), NULLIF(t.network_zone_id,''), NULLIF(t.ssid,''), NULLIF(t.nas_ip,'')::inet
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::timestamptz[], $13::timestamptz[], $14::float8[], $15::text[], $16::text[], $17::text[], $18::text[], $19::text[], $20::text[])
  AS t(event_id, endpoint_id, account_id, entity_role, access_id, access_type, ap, switch_id, switch_port, vlan, source, first_seen, last_seen, confidence, sample, campus_id, building_id, network_zone_id, ssid, nas_ip)
ON CONFLICT(event_id) DO UPDATE SET
  endpoint_id = EXCLUDED.endpoint_id,
  account_id = EXCLUDED.account_id,
  entity_role = EXCLUDED.entity_role,
  access_id = EXCLUDED.access_id,
  access_type = EXCLUDED.access_type,
  ap = EXCLUDED.ap,
  switch_id = EXCLUDED.switch_id,
  switch_port = EXCLUDED.switch_port,
  vlan = EXCLUDED.vlan,
  source = EXCLUDED.source,
  last_seen = GREATEST(identity_access_history.last_seen, EXCLUDED.last_seen),
  identity_confidence = GREATEST(identity_access_history.identity_confidence, EXCLUDED.identity_confidence),
  event_ids_sample = EXCLUDED.event_ids_sample`,
		eventID, endpointID, accountID, entityRole, accessID, accessType, ap, switchID, switchPort, vlan, source,
		firstSeen, lastSeen, confidence, sample, campusID, buildingID, networkZoneID, ssid, nasIP)
	return err
}

func extendAccessHistoryWindows(ctx context.Context, tx *sql.Tx, eventID []string, lastSeen []time.Time) error {
	if len(eventID) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
UPDATE identity_access_history h
SET last_seen = GREATEST(h.last_seen, v.last_seen)
FROM (SELECT * FROM unnest($1::text[], $2::timestamptz[]) AS t(event_id, last_seen)) v
WHERE h.event_id = v.event_id AND h.last_seen < v.last_seen`,
		eventID, lastSeen)
	return err
}

func upsertEndpointEntitiesBatch(ctx context.Context, tx *sql.Tx, items []EndpointEntity) error {
	if len(items) == 0 {
		return nil
	}
	filtered := make([]EndpointEntity, 0, len(items))
	for _, item := range items {
		if item.EndpointID != "" {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].EndpointID < filtered[j].EndpointID })

	endpointID := make([]string, len(filtered))
	primaryMAC := make([]string, len(filtered))
	entityRole := make([]string, len(filtered))
	firstSeen := make([]time.Time, len(filtered))
	lastSeen := make([]time.Time, len(filtered))
	confidence := make([]float64, len(filtered))
	attributes := make([]string, len(filtered))
	for index, item := range filtered {
		endpointID[index], primaryMAC[index], entityRole[index] = item.EndpointID, item.PrimaryMAC, item.EntityRole
		firstSeen[index], lastSeen[index] = identitySQLTime(item.FirstSeen), identitySQLTime(item.LastSeen)
		confidence[index], attributes[index] = item.IdentityConfidence, jsonText(item.Attributes)
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO endpoint_entities(endpoint_id, primary_mac, entity_role, first_seen, last_seen, identity_confidence, attributes)
SELECT t.endpoint_id, t.primary_mac, t.entity_role, t.first_seen, t.last_seen, t.confidence, NULLIF(t.attributes,'')::jsonb
FROM unnest($1::text[], $2::text[], $3::text[], $4::timestamptz[], $5::timestamptz[], $6::float8[], $7::text[])
  AS t(endpoint_id, primary_mac, entity_role, first_seen, last_seen, confidence, attributes)
ON CONFLICT(endpoint_id) DO UPDATE SET
  primary_mac = COALESCE(endpoint_entities.primary_mac, EXCLUDED.primary_mac),
  entity_role = EXCLUDED.entity_role,
  first_seen = LEAST(endpoint_entities.first_seen, EXCLUDED.first_seen),
  last_seen = GREATEST(endpoint_entities.last_seen, EXCLUDED.last_seen),
  identity_confidence = GREATEST(endpoint_entities.identity_confidence, EXCLUDED.identity_confidence),
  attributes = CASE WHEN EXCLUDED.last_seen >= endpoint_entities.last_seen THEN endpoint_entities.attributes || EXCLUDED.attributes ELSE EXCLUDED.attributes || endpoint_entities.attributes END,
  updated_at = now()`,
		endpointID, primaryMAC, entityRole, firstSeen, lastSeen, confidence, attributes)
	return err
}

func upsertInfrastructureEntitiesBatch(ctx context.Context, tx *sql.Tx, items []InfrastructureEntity) error {
	if len(items) == 0 {
		return nil
	}
	filtered := make([]InfrastructureEntity, 0, len(items))
	for _, item := range items {
		if item.EntityID != "" {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].EntityID < filtered[j].EntityID })

	entityID := make([]string, len(filtered))
	ip := make([]string, len(filtered))
	mac := make([]string, len(filtered))
	entityRole := make([]string, len(filtered))
	name := make([]string, len(filtered))
	source := make([]string, len(filtered))
	firstSeen := make([]time.Time, len(filtered))
	lastSeen := make([]time.Time, len(filtered))
	attributes := make([]string, len(filtered))
	for index, item := range filtered {
		entityID[index], ip[index], mac[index] = item.EntityID, item.IP, item.MAC
		entityRole[index], name[index], source[index] = item.EntityRole, item.Name, item.Source
		firstSeen[index], lastSeen[index] = identitySQLTime(item.FirstSeen), identitySQLTime(item.LastSeen)
		attributes[index] = jsonText(item.Attributes)
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO infrastructure_entities(entity_id, ip, mac, entity_role, name, source, first_seen, last_seen, attributes)
SELECT t.entity_id, NULLIF(t.ip,'')::inet, t.mac, t.entity_role, t.name, t.source, t.first_seen, t.last_seen, NULLIF(t.attributes,'')::jsonb
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[], $8::timestamptz[], $9::text[])
  AS t(entity_id, ip, mac, entity_role, name, source, first_seen, last_seen, attributes)
ON CONFLICT(entity_id) DO UPDATE SET
  ip = COALESCE(EXCLUDED.ip, infrastructure_entities.ip),
  mac = COALESCE(EXCLUDED.mac, infrastructure_entities.mac),
  entity_role = EXCLUDED.entity_role,
  name = COALESCE(EXCLUDED.name, infrastructure_entities.name),
  first_seen = LEAST(infrastructure_entities.first_seen, EXCLUDED.first_seen),
  last_seen = GREATEST(infrastructure_entities.last_seen, EXCLUDED.last_seen),
  attributes = infrastructure_entities.attributes || EXCLUDED.attributes,
  updated_at = now()`,
		entityID, ip, mac, entityRole, name, source, firstSeen, lastSeen, attributes)
	return err
}

func upsertAccountSessionsBatch(ctx context.Context, tx *sql.Tx, items []AccountSession) error {
	if len(items) == 0 {
		return nil
	}
	filtered := make([]AccountSession, 0, len(items))
	for _, item := range items {
		if item.SessionID != "" && item.AccountID != "" {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].SessionID < filtered[j].SessionID })

	sessionID := make([]string, len(filtered))
	accountID := make([]string, len(filtered))
	endpointID := make([]string, len(filtered))
	ip := make([]string, len(filtered))
	mac := make([]string, len(filtered))
	accessID := make([]string, len(filtered))
	source := make([]string, len(filtered))
	startedAt := make([]time.Time, len(filtered))
	endedAt := make([]time.Time, len(filtered))
	endedValid := make([]bool, len(filtered))
	confidence := make([]float64, len(filtered))
	rawRef := make([]string, len(filtered))
	personType := make([]string, len(filtered))
	department := make([]string, len(filtered))
	campusID := make([]string, len(filtered))
	buildingID := make([]string, len(filtered))
	networkZoneID := make([]string, len(filtered))
	ssid := make([]string, len(filtered))
	vlan := make([]string, len(filtered))
	ap := make([]string, len(filtered))
	nasIP := make([]string, len(filtered))
	sessionStatus := make([]string, len(filtered))
	confirmedAt := make([]string, len(filtered))
	for index, item := range filtered {
		sessionID[index], accountID[index], endpointID[index] = item.SessionID, item.AccountID, item.EndpointID
		ip[index], mac[index], accessID[index], source[index] = item.IP, item.MAC, item.AccessID, item.Source
		startedAt[index] = identitySQLTime(item.StartedAt)
		if ended, ok := parseTime(item.EndedAt); ok {
			endedAt[index], endedValid[index] = ended, true
		}
		confidence[index], rawRef[index] = item.IdentityConfidence, jsonText(item.RawRef)
		personType[index], department[index], campusID[index] = item.PersonType, item.Department, item.CampusID
		buildingID[index], networkZoneID[index], ssid[index] = item.BuildingID, item.NetworkZoneID, item.SSID
		vlan[index], ap[index], nasIP[index], sessionStatus[index] = item.VLAN, item.AP, item.NASIP, item.SessionStatus
		confirmedAt[index] = item.LastConfirmedAt
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO account_sessions(session_id, account_id, endpoint_id, ip, mac, access_id, source, started_at, ended_at, identity_confidence, raw_ref, person_type, department, campus_id, building_id, network_zone_id, ssid, vlan, ap, nas_ip, session_status)
SELECT t.session_id, t.account_id, t.endpoint_id, NULLIF(t.ip,'')::inet, t.mac, t.access_id, t.source, t.started_at, CASE WHEN t.ended_valid THEN t.ended_at ELSE NULL END, t.confidence, t.raw_ref::jsonb, NULLIF(t.person_type,''), NULLIF(t.department,''), NULLIF(t.campus_id,''), NULLIF(t.building_id,''), NULLIF(t.network_zone_id,''), NULLIF(t.ssid,''), NULLIF(t.vlan,''), NULLIF(t.ap,''), NULLIF(t.nas_ip,'')::inet, NULLIF(t.session_status,'')
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::timestamptz[], $9::timestamptz[], $10::boolean[], $11::float8[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[], $17::text[], $18::text[], $19::text[], $20::text[], $21::text[], $22::text[])
  AS t(session_id, account_id, endpoint_id, ip, mac, access_id, source, started_at, ended_at, ended_valid, confidence, raw_ref, person_type, department, campus_id, building_id, network_zone_id, ssid, vlan, ap, nas_ip, session_status)
ON CONFLICT(session_id) DO UPDATE SET
  account_id = EXCLUDED.account_id,
  endpoint_id = EXCLUDED.endpoint_id,
  ip = EXCLUDED.ip,
  mac = EXCLUDED.mac,
  access_id = EXCLUDED.access_id,
  source = EXCLUDED.source,
  started_at = LEAST(account_sessions.started_at, EXCLUDED.started_at),
  ended_at = COALESCE(EXCLUDED.ended_at, account_sessions.ended_at),
  identity_confidence = GREATEST(account_sessions.identity_confidence, EXCLUDED.identity_confidence),
  raw_ref = account_sessions.raw_ref || EXCLUDED.raw_ref,
  person_type = COALESCE(EXCLUDED.person_type, account_sessions.person_type),
  department = COALESCE(EXCLUDED.department, account_sessions.department),
  campus_id = COALESCE(EXCLUDED.campus_id, account_sessions.campus_id),
  building_id = COALESCE(EXCLUDED.building_id, account_sessions.building_id),
  network_zone_id = COALESCE(EXCLUDED.network_zone_id, account_sessions.network_zone_id),
  ssid = COALESCE(EXCLUDED.ssid, account_sessions.ssid),
  vlan = COALESCE(EXCLUDED.vlan, account_sessions.vlan),
  ap = COALESCE(EXCLUDED.ap, account_sessions.ap),
  nas_ip = COALESCE(EXCLUDED.nas_ip, account_sessions.nas_ip),
  session_status = COALESCE(EXCLUDED.session_status, account_sessions.session_status),
  updated_at = now()`,
		sessionID, accountID, endpointID, ip, mac, accessID, source, startedAt, endedAt, endedValid, confidence, rawRef,
		personType, department, campusID, buildingID, networkZoneID, ssid, vlan, ap, nasIP, sessionStatus)
	if err != nil {
		return err
	}
	metadata := make([]string, len(filtered))
	for index, item := range filtered {
		metadata[index] = jsonText(item)
	}
	_, err = tx.ExecContext(ctx, `
UPDATE account_sessions s SET policy_metadata = NULLIF(v.metadata,'')::jsonb
FROM (SELECT * FROM unnest($1::text[], $2::text[], $3::text[]) AS t(session_id, metadata, confirmed_at)) v
WHERE s.session_id = v.session_id
  AND COALESCE(NULLIF(s.policy_metadata->>'last_confirmed_at','')::timestamptz,'-infinity'::timestamptz) <= COALESCE(NULLIF(v.confirmed_at,'')::timestamptz,'-infinity'::timestamptz)`,
		sessionID, metadata, confirmedAt)
	return err
}

func insertDeviceLeasesBatch(ctx context.Context, tx *sql.Tx, leases []deviceLease) error {
	if len(leases) == 0 {
		return nil
	}
	leases = append([]deviceLease(nil), leases...)
	sort.SliceStable(leases, func(i, j int) bool {
		if leases[i].Sensor != leases[j].Sensor {
			return leases[i].Sensor < leases[j].Sensor
		}
		return leases[i].EventID < leases[j].EventID
	})
	sensor := make([]string, len(leases))
	campus := make([]string, len(leases))
	eventID := make([]string, len(leases))
	ip := make([]string, len(leases))
	endpoint := make([]string, len(leases))
	observedAt := make([]time.Time, len(leases))
	validUntil := make([]time.Time, len(leases))
	action := make([]string, len(leases))
	for index, lease := range leases {
		sensor[index], campus[index], eventID[index], ip[index] = lease.Sensor, lease.Campus, lease.EventID, lease.IP
		endpoint[index], observedAt[index], validUntil[index], action[index] = lease.Endpoint, lease.At, lease.Until, lease.Action
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO device_address_leases(sensor_id, campus_id, event_id, ip, endpoint_id, observed_at, valid_until, action)
SELECT t.sensor_id, t.campus_id, t.event_id, t.ip::inet, t.endpoint_id, t.observed_at, t.valid_until, t.action
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::timestamptz[], $7::timestamptz[], $8::text[])
  AS t(sensor_id, campus_id, event_id, ip, endpoint_id, observed_at, valid_until, action)
ON CONFLICT DO NOTHING`,
		sensor, campus, eventID, ip, endpoint, observedAt, validUntil, action)
	return err
}

func upsertEndpointDeviceProfilesBatch(ctx context.Context, tx *sql.Tx, items []EndpointDeviceInventory) error {
	if len(items) == 0 {
		return nil
	}
	filtered := make([]EndpointDeviceInventory, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		if item.EndpointID == "" || seen[item.EndpointID] {
			continue
		}
		seen[item.EndpointID] = true
		filtered = append(filtered, item)
	}
	if len(filtered) == 0 {
		return nil
	}
	// Only profiles whose content actually changed are written. The identity path rebuilds
	// every endpoint's profile on every batch, and on the field that meant rewriting rows
	// that almost never change: 687k updates against a 28 MB heap. Unchanged endpoints are
	// now skipped after one indexed read.
	changed, err := changedEndpointDeviceProfiles(ctx, tx, filtered)
	if err != nil {
		return err
	}
	filtered = changed
	if len(filtered) == 0 {
		return nil
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].EndpointID < filtered[j].EndpointID })

	endpointID := make([]string, len(filtered))
	vendor := make([]string, len(filtered))
	brand := make([]string, len(filtered))
	model := make([]string, len(filtered))
	deviceType := make([]string, len(filtered))
	osFamily := make([]string, len(filtered))
	recognitionConfidence := make([]float64, len(filtered))
	vendorConfidence := make([]float64, len(filtered))
	brandConfidence := make([]float64, len(filtered))
	modelConfidence := make([]float64, len(filtered))
	deviceTypeConfidence := make([]float64, len(filtered))
	osFamilyConfidence := make([]float64, len(filtered))
	recognitionSource := make([]string, len(filtered))
	fingerprintVersion := make([]string, len(filtered))
	randomizedMAC := make([]bool, len(filtered))
	recognitionConflict := make([]bool, len(filtered))
	evidenceSummary := make([]string, len(filtered))
	for index, item := range filtered {
		endpointID[index], vendor[index], brand[index], model[index] = item.EndpointID, item.Vendor, item.Brand, item.Model
		deviceType[index], osFamily[index] = item.DeviceType, item.OSFamily
		recognitionConfidence[index], vendorConfidence[index], brandConfidence[index] = item.RecognitionConfidence, item.VendorConfidence, item.BrandConfidence
		modelConfidence[index], deviceTypeConfidence[index], osFamilyConfidence[index] = item.ModelConfidence, item.DeviceTypeConfidence, item.OSFamilyConfidence
		recognitionSource[index], fingerprintVersion[index] = item.RecognitionSource, item.FingerprintVersion
		randomizedMAC[index], recognitionConflict[index] = item.RandomizedMAC, item.RecognitionConflict
		evidenceSummary[index] = jsonText(map[string]any{
			"summary":        item.Summary,
			"source":         item.RecognitionSource,
			"randomized_mac": item.RandomizedMAC,
		})
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO endpoint_device_profiles(endpoint_id, vendor, brand, model, device_type, os_family, recognition_confidence, vendor_confidence, brand_confidence, model_confidence, device_type_confidence, os_family_confidence, recognition_source, fingerprint_version, randomized_mac, recognition_conflict, evidence_summary)
SELECT t.endpoint_id, t.vendor, t.brand, t.model, t.device_type, t.os_family, t.recognition_confidence, t.vendor_confidence, t.brand_confidence, t.model_confidence, t.device_type_confidence, t.os_family_confidence, t.recognition_source, t.fingerprint_version, t.randomized_mac, t.recognition_conflict, NULLIF(t.evidence_summary,'')::jsonb
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::float8[], $8::float8[], $9::float8[], $10::float8[], $11::float8[], $12::float8[], $13::text[], $14::text[], $15::boolean[], $16::boolean[], $17::text[])
  AS t(endpoint_id, vendor, brand, model, device_type, os_family, recognition_confidence, vendor_confidence, brand_confidence, model_confidence, device_type_confidence, os_family_confidence, recognition_source, fingerprint_version, randomized_mac, recognition_conflict, evidence_summary)
ON CONFLICT(endpoint_id) DO UPDATE SET
  vendor = EXCLUDED.vendor,
  brand = EXCLUDED.brand,
  model = EXCLUDED.model,
  device_type = EXCLUDED.device_type,
  os_family = EXCLUDED.os_family,
  recognition_confidence = EXCLUDED.recognition_confidence,
  vendor_confidence = EXCLUDED.vendor_confidence,
  brand_confidence = EXCLUDED.brand_confidence,
  model_confidence = EXCLUDED.model_confidence,
  device_type_confidence = EXCLUDED.device_type_confidence,
  os_family_confidence = EXCLUDED.os_family_confidence,
  recognition_source = EXCLUDED.recognition_source,
  fingerprint_version = EXCLUDED.fingerprint_version,
  randomized_mac = EXCLUDED.randomized_mac,
  recognition_conflict = EXCLUDED.recognition_conflict,
  evidence_summary = EXCLUDED.evidence_summary,
  updated_at = now()`,
		endpointID, vendor, brand, model, deviceType, osFamily, recognitionConfidence, vendorConfidence, brandConfidence,
		modelConfidence, deviceTypeConfidence, osFamilyConfidence, recognitionSource, fingerprintVersion, randomizedMAC,
		recognitionConflict, evidenceSummary)
	return err
}

// policyIdentityRow is one row of policy_identity_observations before serialization.
type policyIdentityRow struct {
	EventID     string
	ConfirmedAt time.Time
	AccountID   string
	SessionID   string
	SessionData string
}

func insertPolicyIdentityObservationsBatch(ctx context.Context, tx *sql.Tx, rows []policyIdentityRow) error {
	if len(rows) == 0 {
		return nil
	}
	rows = append([]policyIdentityRow(nil), rows...)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].EventID < rows[j].EventID })

	eventID := make([]string, len(rows))
	observedAt := make([]time.Time, len(rows))
	accountID := make([]string, len(rows))
	sessionID := make([]string, len(rows))
	sessionData := make([]string, len(rows))
	for index, row := range rows {
		eventID[index], observedAt[index], accountID[index], sessionID[index] = row.EventID, row.ConfirmedAt, row.AccountID, row.SessionID
		sessionData[index] = row.SessionData
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO policy_identity_observations(event_id, observed_at, account_id, session_id, session_data)
SELECT t.event_id, t.observed_at, t.account_id, t.session_id, NULLIF(t.session_data,'')::jsonb
FROM unnest($1::text[], $2::timestamptz[], $3::text[], $4::text[], $5::text[])
  AS t(event_id, observed_at, account_id, session_id, session_data)
ON CONFLICT(event_id) DO NOTHING`,
		eventID, observedAt, accountID, sessionID, sessionData)
	return err
}

// upsertDeviceSignalFactsBatch replaces the per-signal trio of statements with three
// statements for the whole batch, including the seen_count aggregate that used to run a
// correlated window function once per signal.
func upsertDeviceSignalFactsBatch(ctx context.Context, tx *sql.Tx, sensorID string, signals []DeviceSignal) error {
	if len(signals) == 0 {
		return nil
	}
	signals = append([]DeviceSignal(nil), signals...)
	sort.SliceStable(signals, func(i, j int) bool { return signals[i].SignalID < signals[j].SignalID })

	signalID := make([]string, len(signals))
	ip := make([]string, len(signals))
	source := make([]string, len(signals))
	kind := make([]string, len(signals))
	value := make([]string, len(signals))
	normalized := make([]string, len(signals))
	strength := make([]string, len(signals))
	confidence := make([]float64, len(signals))
	weight := make([]int64, len(signals))
	firstSeen := make([]time.Time, len(signals))
	lastSeen := make([]time.Time, len(signals))
	sample := make([]string, len(signals))
	eventSignalID := []string{}
	eventEventID := []string{}
	eventFirstSeen := []time.Time{}
	now := time.Now()
	for index, signal := range signals {
		signalID[index], ip[index], source[index] = signal.SignalID, signal.IP, signal.Source
		kind[index], value[index], normalized[index], strength[index] = signal.Kind, signal.Value, signal.NormalizedValue, signal.Strength
		confidence[index], weight[index] = signal.Confidence, int64(signal.Weight)
		start := nullableTime(signal.FirstSeen)
		end := nullableTime(signal.LastSeen)
		if !start.Valid && end.Valid {
			start = end
		}
		if !end.Valid && start.Valid {
			end = start
		}
		if !start.Valid || !end.Valid {
			start = sql.NullTime{Time: now, Valid: true}
			end = sql.NullTime{Time: now, Valid: true}
		}
		firstSeen[index], lastSeen[index] = start.Time, end.Time
		sample[index] = jsonText(signalEventIDs(signal))
		for _, eventID := range signalEventIDs(signal) {
			eventSignalID = append(eventSignalID, signal.SignalID)
			eventEventID = append(eventEventID, eventID)
			eventFirstSeen = append(eventFirstSeen, start.Time)
		}
	}
	// The signal facts are keyed by (sensor_id, signal_id); the duplicate signal ids that
	// a batch can contain are collapsed by the conflict update, so deduplicate the
	// arrays first to keep the statement from updating the same row twice.
	facts := map[string]int{}
	for index, id := range signalID {
		facts[id] = index
	}
	unique := make([]int, 0, len(facts))
	for _, index := range facts {
		unique = append(unique, index)
	}
	sort.Ints(unique)
	pick := func(values []string) []string {
		out := make([]string, 0, len(unique))
		for _, index := range unique {
			out = append(out, values[index])
		}
		return out
	}
	pickFloat := func(values []float64) []float64 {
		out := make([]float64, 0, len(unique))
		for _, index := range unique {
			out = append(out, values[index])
		}
		return out
	}
	pickInt := func(values []int64) []int64 {
		out := make([]int64, 0, len(unique))
		for _, index := range unique {
			out = append(out, values[index])
		}
		return out
	}
	pickTime := func(values []time.Time) []time.Time {
		out := make([]time.Time, 0, len(unique))
		for _, index := range unique {
			out = append(out, values[index])
		}
		return out
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO device_signal_facts(sensor_id, signal_id, ip, source, kind, value, normalized_value, strength, confidence, weight, first_seen, last_seen, seen_count, event_ids_sample)
SELECT $1, t.signal_id, t.ip::inet, t.source, t.kind, t.value, t.normalized_value, t.strength, t.confidence, t.weight::int, t.first_seen, t.last_seen, 0, NULLIF(t.sample,'')::jsonb
FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::float8[], $10::bigint[], $11::timestamptz[], $12::timestamptz[], $13::text[])
  AS t(signal_id, ip, source, kind, value, normalized_value, strength, confidence, weight, first_seen, last_seen, sample)
ON CONFLICT(sensor_id, signal_id) DO UPDATE SET
  value = EXCLUDED.value,
  confidence = GREATEST(device_signal_facts.confidence, EXCLUDED.confidence),
  weight = GREATEST(device_signal_facts.weight, EXCLUDED.weight),
  first_seen = LEAST(device_signal_facts.first_seen, EXCLUDED.first_seen),
  last_seen = GREATEST(device_signal_facts.last_seen, EXCLUDED.last_seen),
  updated_at = now()`,
		sensorID, pick(signalID), pick(ip), pick(source), pick(kind), pick(value), pick(normalized), pick(strength),
		pickFloat(confidence), pickInt(weight), pickTime(firstSeen), pickTime(lastSeen), pick(sample))
	if err != nil {
		return err
	}
	if len(eventEventID) > 0 {
		if _, err = tx.ExecContext(ctx, `
INSERT INTO device_signal_events(sensor_id, signal_id, event_id, first_seen)
SELECT $1, t.signal_id, t.event_id, t.first_seen
FROM unnest($2::text[], $3::text[], $4::timestamptz[]) AS t(signal_id, event_id, first_seen)
ON CONFLICT(sensor_id, signal_id, event_id) DO NOTHING`,
			sensorID, eventSignalID, eventEventID, eventFirstSeen); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `
UPDATE device_signal_facts f
SET seen_count = counted.seen_count,
    event_ids_sample = COALESCE(counted.event_ids_sample, '[]'::jsonb),
    updated_at = now()
FROM (
  SELECT signal_id, count(*) AS seen_count,
         jsonb_agg(event_id ORDER BY first_seen DESC, event_id) FILTER (WHERE event_rank <= 20) AS event_ids_sample
  FROM (
    SELECT signal_id, event_id, first_seen,
           row_number() OVER (PARTITION BY signal_id ORDER BY first_seen DESC, event_id) AS event_rank
    FROM device_signal_events
    WHERE sensor_id = $1 AND signal_id = ANY($2::text[])
  ) ranked
  GROUP BY signal_id
) counted
WHERE f.sensor_id = $1 AND f.signal_id = counted.signal_id`,
		sensorID, pick(signalID))
	return err
}

// changedEndpointDeviceProfiles keeps the items whose stored profile differs. A missing
// stored row always counts as changed.
func changedEndpointDeviceProfiles(ctx context.Context, tx *sql.Tx, items []EndpointDeviceInventory) ([]EndpointDeviceInventory, error) {
	if len(items) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.EndpointID)
	}
	rows, err := tx.QueryContext(ctx, `SELECT endpoint_id, vendor, brand, model, device_type, os_family, recognition_confidence, vendor_confidence, brand_confidence, model_confidence, device_type_confidence, os_family_confidence, recognition_source, fingerprint_version, randomized_mac, recognition_conflict
FROM endpoint_device_profiles WHERE endpoint_id = ANY($1::text[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type profileKey struct {
		vendor, brand, model, deviceType, osFamily string
		recognitionSource, fingerprintVersion      string
		recognitionConfidence, vendorConfidence    float64
		brandConfidence, modelConfidence           float64
		deviceTypeConfidence, osFamilyConfidence   float64
		randomizedMAC, recognitionConflict         bool
	}
	stored := map[string]profileKey{}
	for rows.Next() {
		var key profileKey
		var endpointID string
		if err = rows.Scan(&endpointID, &key.vendor, &key.brand, &key.model, &key.deviceType, &key.osFamily,
			&key.recognitionConfidence, &key.vendorConfidence, &key.brandConfidence, &key.modelConfidence,
			&key.deviceTypeConfidence, &key.osFamilyConfidence, &key.recognitionSource, &key.fingerprintVersion,
			&key.randomizedMAC, &key.recognitionConflict); err != nil {
			return nil, err
		}
		stored[endpointID] = key
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out := make([]EndpointDeviceInventory, 0, len(items))
	for _, item := range items {
		current, found := stored[item.EndpointID]
		if !found {
			out = append(out, item)
			continue
		}
		if current.vendor != item.Vendor || current.brand != item.Brand || current.model != item.Model ||
			current.deviceType != item.DeviceType || current.osFamily != item.OSFamily ||
			current.recognitionConfidence != item.RecognitionConfidence || current.vendorConfidence != item.VendorConfidence ||
			current.brandConfidence != item.BrandConfidence || current.modelConfidence != item.ModelConfidence ||
			current.deviceTypeConfidence != item.DeviceTypeConfidence || current.osFamilyConfidence != item.OSFamilyConfidence ||
			current.recognitionSource != item.RecognitionSource || current.fingerprintVersion != item.FingerprintVersion ||
			current.randomizedMAC != item.RandomizedMAC || current.recognitionConflict != item.RecognitionConflict {
			out = append(out, item)
		}
	}
	return out, nil
}

// Identity write serialisation.
//
// identityWriteLockKey is a single advisory key for every identity writer in the cluster:
// they all materialize the same endpoint, session and history rows, so the only way to
// avoid cross-writer lock queues is to admit one writer at a time.
const identityWriteLockSQL = `SELECT pg_try_advisory_xact_lock(hashtextextended('proxy-sentinel-identity-write', 7137))`

// tryIdentityWriteLock reports whether this transaction may write identity state now. The
// materializers use it to skip a batch instead of queueing behind another writer.
func tryIdentityWriteLock(ctx context.Context, tx *sql.Tx) (bool, error) {
	if err := boundIdentityStatements(ctx, tx); err != nil {
		return false, err
	}
	var locked bool
	if err := tx.QueryRowContext(ctx, identityWriteLockSQL).Scan(&locked); err != nil {
		return false, err
	}
	return locked, nil
}

// lockIdentityWrite waits for the identity write lock. The transaction's deadline bounds
// the wait, and this transaction already holding the lock may take it again.
func lockIdentityWrite(ctx context.Context, tx *sql.Tx) error {
	if err := boundIdentityStatements(ctx, tx); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('proxy-sentinel-identity-write', 7137))`)
	return err
}

// identityLockWaitStep is the pause between attempts while a live lane waits for the
// identity write lock.
const identityLockWaitStep = 250 * time.Millisecond

// awaitIdentityWriteLock waits up to budget for the identity write lock and reports
// whether this transaction now holds it.
//
// tryIdentityWriteLock alone starves the live lane. The domain worker holds the same lock
// across the identity phase of every batch — one measured batch spent 49.045s of its
// 49.058s total in that phase — and it re-acquires immediately, so sampling the lock on
// the field returned "held" on 10 of 10 attempts across 20 seconds. A lane that skips
// instead of waiting therefore never runs: the identity materializer's live cursor sat
// frozen at 2026-10-13 15:20:45 for tens of minutes with an empty last_error, and
// endpoint_entities stopped advancing, which is the device center going stale. Waiting a
// bounded time turns that silent starvation into a delay.
func awaitIdentityWriteLock(ctx context.Context, tx *sql.Tx, budget time.Duration) (bool, error) {
	deadline := time.Now().Add(budget)
	for {
		locked, err := tryIdentityWriteLock(ctx, tx)
		if err != nil || locked {
			return locked, err
		}
		if !time.Now().After(deadline) {
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(identityLockWaitStep):
				continue
			}
		}
		return false, nil
	}
}

// Client cancellation alone can leave a disconnected backend doing expensive
// history I/O while retaining its advisory lock. Enforce the remaining budget
// inside PostgreSQL as well; SET LOCAL never changes other connections.
func boundIdentityStatements(ctx context.Context, tx *sql.Tx) error {
	budget := identityWorkBudget
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline))
	}
	if budget <= 0 {
		return context.DeadlineExceeded
	}
	_, err := tx.ExecContext(ctx, `SELECT set_config('statement_timeout',$1,true)`, strconv.FormatInt(max(1, budget.Milliseconds()), 10))
	return err
}
