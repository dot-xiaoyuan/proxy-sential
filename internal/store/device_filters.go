package store

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// Facets include all discovered endpoint recognition clues, independent of pagination and selections.
type DeviceFilterFacets struct {
	Brands     []string `json:"brands"`
	OSFamilies []string `json:"os_families"`
}

func deviceFilterValues(item EndpointDeviceInventory) (brand, osFamily string) {
	if !item.RecognitionConflict {
		brand, osFamily = strings.TrimSpace(item.Brand), strings.TrimSpace(item.OSFamily)
	}
	if item.BrandInference != nil && item.BrandInference.Status == "inferred" && (item.BrandConfidence < .8 || item.RecognitionConflict) {
		brand = item.BrandInference.Brand
	}
	if brand == "" || strings.EqualFold(brand, "unknown") {
		brand = ""
		if item.BrandInference != nil && item.BrandInference.Status == "inferred" {
			brand = item.BrandInference.Brand
		}
	}
	if !item.RecognitionConflict && item.BrandReference != nil && (brand == "" || item.BrandConfidence < .8) && (item.BrandInference == nil || item.BrandInference.Status == "insufficient") {
		brand = item.BrandReference.Brand
	}
	if brand == "" {
		brand = "unknown"
	}
	if osFamily == "" || strings.EqualFold(osFamily, "unknown") {
		osFamily = "unknown"
	}
	return
}

func deviceRecognitionMatches(item EndpointDeviceInventory, query Query) bool {
	brand, osFamily := deviceFilterValues(item)
	return (query.Brand == "" || strings.EqualFold(query.Brand, brand)) && (query.OSFamily == "" || strings.EqualFold(query.OSFamily, osFamily))
}

func deviceFilterFacets(items []EndpointDeviceInventory) DeviceFilterFacets {
	brands, systems := map[string]string{}, map[string]string{}
	for _, item := range items {
		brand, osFamily := deviceFilterValues(item)
		for _, pair := range []struct {
			values map[string]string
			value  string
		}{{brands, brand}, {systems, osFamily}} {
			key := strings.ToLower(pair.value)
			if old, ok := pair.values[key]; !ok || pair.value < old {
				pair.values[key] = pair.value
			}
		}
	}
	values := func(m map[string]string) []string {
		out := make([]string, 0, len(m))
		for _, value := range m {
			out = append(out, value)
		}
		sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
		return out
	}
	return DeviceFilterFacets{Brands: values(brands), OSFamilies: values(systems)}
}

// Load recognition metadata in two queries; do not load every endpoint's IP/session history.
func (s *PostgresStore) loadEndpointRecognitionCatalog(ctx context.Context) ([]EndpointDeviceInventory, error) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_RECOGNITION_SUMMARY_V1")), "true") {
		rows, err := s.db.QueryContext(ctx, `SELECT summary FROM endpoint_recognition_summary ORDER BY endpoint_id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := []EndpointDeviceInventory{}
		for rows.Next() {
			var raw []byte
			if err = rows.Scan(&raw); err != nil {
				return nil, err
			}
			var item EndpointDeviceInventory
			if err = json.Unmarshal(raw, &item); err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, rows.Err()
	}
	rows, err := s.db.QueryContext(ctx, `SELECT to_jsonb(e) FROM endpoint_entities e WHERE entity_role='endpoint'`)
	if err != nil {
		return nil, err
	}
	endpoints := []EndpointEntity{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		var endpoint EndpointEntity
		if err := json.Unmarshal(raw, &endpoint); err != nil {
			rows.Close()
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	snapshot := ctx.Value(domainReadKey{}).(domainReadSnapshot)
	ids := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		ids = append(ids, endpoint.EndpointID)
	}
	passiveHints, err := s.PassiveDiscoveryRecognitionHints(ctx, ids, snapshot.now)
	if err != nil {
		return nil, err
	}
	items := make([]EndpointDeviceInventory, 0, len(endpoints))
	for _, endpoint := range endpoints {
		items = append(items, BuildEndpointDeviceInventory(EndpointIdentityProfile{
			EndpointID: endpoint.EndpointID, Endpoint: endpoint, DiscoveryRecognitionHints: passiveHints[endpoint.EndpointID],
		}))
	}
	evidence, err := s.endpointDomainEvidenceBatch(ctx, ids)
	if err != nil {
		return nil, err
	}

	for i := range items {
		items[i].domainEvidence = evidence[items[i].EndpointID]
		applyDomainRecognition(&items[i], evidence[items[i].EndpointID], snapshot.version, snapshot.now, snapshot.enabled)
	}
	return items, nil
}
