package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

func (s *PostgresStore) endpointDomainEvidenceBatch(ctx context.Context, ids []string) (map[string][]fingerprint.DomainEvidence, error) {
	snapshot := ctx.Value(domainReadKey{}).(domainReadSnapshot)
	rows, err := s.db.QueryContext(ctx, `SELECT endpoint_id,rule_match,coalesce(observation->>'event_source',''),coalesce(min(observation->>'attribution_method'),''),min(observed_at),max(observed_at),count(*),to_json((array_agg(event_id ORDER BY observed_at,event_id))[1:10]) FROM endpoint_domain_evidence_events WHERE endpoint_id=ANY($1::text[]) AND rule_version=$2 AND observed_at BETWEEN $3 AND $4 AND rule_match IS NOT NULL GROUP BY endpoint_id,rule_match,observation->>'event_source' ORDER BY endpoint_id,min(observed_at),rule_match::text,observation->>'event_source'`, ids, snapshot.version, snapshot.now.Add(-fingerprint.BrandEvidenceWindow), snapshot.now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]fingerprint.DomainEvidence{}
	for rows.Next() {
		var id string
		var entry fingerprint.DomainEvidence
		var raw, eventIDs []byte
		var first, last time.Time
		if err = rows.Scan(&id, &raw, &entry.EventSource, &entry.AttributionMethod, &first, &last, &entry.Count, &eventIDs); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &entry.Match); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(eventIDs, &entry.EventIDs); err != nil {
			return nil, err
		}
		entry.RuleVersion = snapshot.version
		entry.FirstSeen = first.UTC().Format(time.RFC3339Nano)
		entry.LastSeen = last.UTC().Format(time.RFC3339Nano)
		out[id] = append(out[id], entry)
	}
	return out, rows.Err()
}

// A page projects bounded identity summaries in four SQL queries. Raw history
// payloads stay in the detail path; recognition evidence shares the versioned,
// five-second catalog snapshot instead of repeating its aggregation per page.
func (s *PostgresStore) endpointDevicePage(ctx context.Context, ids []string, catalog []EndpointDeviceInventory, asOf time.Time) ([]EndpointDeviceInventory, error) {
	if len(ids) == 0 {
		return []EndpointDeviceInventory{}, nil
	}
	state := IdentityState{}
	queries := []struct {
		sql  string
		scan func(*sql.Rows) error
	}{
		{`SELECT endpoint_id,primary_mac,entity_role,first_seen,last_seen,identity_confidence,attributes,registration_status,owner_account,owner_name,owner_department,asset_tag,ownership_class,registered_by,registered_at,registration_note,merge_status,merged_into_endpoint_id,split_from_endpoint_id,registration_updated_by,registration_updated_at FROM endpoint_entities WHERE endpoint_id=ANY($1::text[])`, func(rows *sql.Rows) error {
			item, err := scanEndpointEntity(rows)
			state.Endpoints = append(state.Endpoints, item)
			return err
		}},
		{`SELECT h.session_id,h.account_id,h.endpoint_id,'','','','',h.started_at,h.ended_at,0,'','{}'::jsonb FROM unnest($1::text[]) ids(id) JOIN LATERAL(SELECT session_id,account_id,endpoint_id,started_at,ended_at FROM account_sessions WHERE endpoint_id=ids.id ORDER BY started_at DESC,session_id LIMIT 200) h ON true`, func(rows *sql.Rows) error {
			item, err := scanAccountSession(rows)
			state.Sessions = append(state.Sessions, item)
			return err
		}},
		{`SELECT h.event_id,h.endpoint_id,h.account_id,'endpoint',host(h.ip),'','',h.first_seen,h.last_seen,0,'[]'::jsonb FROM unnest($1::text[]) ids(id) JOIN LATERAL(SELECT event_id,endpoint_id,account_id,ip,first_seen,last_seen FROM identity_ip_mac_history WHERE endpoint_id=ids.id ORDER BY last_seen DESC,first_seen DESC,host(ip),event_id LIMIT 200) h ON true`, func(rows *sql.Rows) error {
			item, err := scanIdentityIPMACHistory(rows)
			state.IPMACHistory = append(state.IPMACHistory, item)
			return err
		}},
		{`SELECT h.event_id,h.endpoint_id,h.account_id,'endpoint',h.access_id,'','','','','','',h.first_seen,h.last_seen,0,'[]'::jsonb FROM unnest($1::text[]) ids(id) JOIN LATERAL(SELECT event_id,endpoint_id,account_id,access_id,first_seen,last_seen FROM identity_access_history WHERE endpoint_id=ids.id ORDER BY last_seen DESC,event_id LIMIT 200) h ON true`, func(rows *sql.Rows) error {
			item, err := scanIdentityAccessHistory(rows)
			state.AccessHistory = append(state.AccessHistory, item)
			return err
		}},
	}
	for _, q := range queries {
		rows, err := s.db.QueryContext(ctx, q.sql, ids)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			if err = q.scan(rows); err != nil {
				rows.Close()
				return nil, err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	evidence := make(map[string][]fingerprint.DomainEvidence, len(ids))
	cachedRecognition := make(map[string]EndpointDeviceInventory, len(catalog))
	for _, cached := range catalog {
		if cached.FingerprintVersion != fingerprint.Default().Version() {
			continue
		}
		evidence[cached.EndpointID] = cached.domainEvidence
		cachedRecognition[cached.EndpointID] = cached
	}
	missing := []string{}
	freshIDs := map[string]bool{}
	for _, id := range ids {
		if _, ok := evidence[id]; !ok {
			missing = append(missing, id)
			freshIDs[id] = true
		}
	}
	if len(missing) > 0 {
		fresh, err := s.endpointDomainEvidenceBatch(ctx, missing)
		if err != nil {
			return nil, err
		}
		for _, id := range missing {
			evidence[id] = fresh[id]
		}
	}
	snapshot := ctx.Value(domainReadKey{}).(domainReadSnapshot)
	passiveHints, err := s.PassiveDiscoveryRecognitionHints(ctx, ids, snapshot.now)
	if err != nil {
		return nil, err
	}
	out := make([]EndpointDeviceInventory, 0, len(ids))
	for _, id := range ids {
		profile, ok := BuildEndpointIdentityProfile(state, id)
		if !ok {
			continue
		}
		profile.DiscoveryRecognitionHints = passiveHints[id]
		item := BuildEndpointDeviceInventory(profile)
		if cached, found := cachedRecognition[id]; found && materializedRecognitionPreferred(item, cached) {
			applyMaterializedRecognition(&item, cached)
		} else {
			recognitionAt := asOf
			if freshIDs[id] {
				recognitionAt = snapshot.now
			}
			applyDomainRecognition(&item, evidence[id], snapshot.version, recognitionAt, snapshot.enabled)
		}
		out = append(out, item)
	}
	return out, nil
}

func materializedRecognitionPreferred(current, cached EndpointDeviceInventory) bool {
	specificity := func(item EndpointDeviceInventory) int {
		count := 0
		for _, value := range []string{item.Brand, item.Model, item.DeviceType, item.OSFamily} {
			if value != "" {
				count++
			}
		}
		return count
	}
	if specificity(current) > specificity(cached) && current.RecognitionConfidence >= cached.RecognitionConfidence {
		return false
	}
	if current.RecognitionSource == "passive_discovery" && cached.RecognitionSource != "passive_discovery" && current.RecognitionConfidence >= cached.RecognitionConfidence {
		return false
	}
	return true
}

func applyMaterializedRecognition(item *EndpointDeviceInventory, cached EndpointDeviceInventory) {
	item.Vendor = cached.Vendor
	item.Brand = cached.Brand
	item.Model = cached.Model
	item.DeviceType = cached.DeviceType
	item.OSFamily = cached.OSFamily
	item.RecognitionConfidence = cached.RecognitionConfidence
	item.VendorConfidence = cached.VendorConfidence
	item.BrandConfidence = cached.BrandConfidence
	item.ModelConfidence = cached.ModelConfidence
	item.DeviceTypeConfidence = cached.DeviceTypeConfidence
	item.OSFamilyConfidence = cached.OSFamilyConfidence
	item.RecognitionSource = cached.RecognitionSource
	item.FingerprintVersion = cached.FingerprintVersion
	item.RandomizedMAC = cached.RandomizedMAC
	item.RecognitionConflict = cached.RecognitionConflict
	item.RecognitionEvidence = append([]string{}, cached.RecognitionEvidence...)
	item.BrandReference = cached.BrandReference
	item.BrandInference = cached.BrandInference
	item.EcosystemHint = cached.EcosystemHint
	item.EcosystemConfidence = cached.EcosystemConfidence
	item.EcosystemConflict = cached.EcosystemConflict
	item.EcosystemEvidenceCount = cached.EcosystemEvidenceCount
	item.Summary = endpointDeviceSummary(*item)
}
