package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"
)

type IndexedDeviceMetadata struct {
	Publication           *ReportPublication        `json:"publication,omitempty"`
	ClassificationVersion string                    `json:"classification_version,omitempty"`
	Total                 int64                     `json:"total"`
	Identified            int64                     `json:"identified"`
	Candidate             int64                     `json:"candidate"`
	Conflict              int64                     `json:"conflict"`
	Expired               int64                     `json:"expired"`
	Types                 []IndexedDeviceTypeCount  `json:"types"`
	CandidateTypes        []IndexedDeviceTypeCount  `json:"candidate_types,omitempty"`
	IPProductTypes        []IndexedDeviceTypeCount  `json:"ip_product_types,omitempty"`
	VLANs                 []IndexedVLANCount        `json:"vlans,omitempty"`
	Overview              *IndexedDiscoveryOverview `json:"overview,omitempty"`
	AsOf                  time.Time                 `json:"as_of"`
	CountUnit             string                    `json:"count_unit"`
	Window                string                    `json:"window"`
}

var discoveryCalendar = time.FixedZone("Asia/Shanghai", 8*60*60)

type IndexedDiscoveryOverview struct {
	Active         int64                 `json:"active"`
	PreviousActive *int64                `json:"previous_active,omitempty"`
	DumbTerminals  int64                 `json:"dumb_terminals"`
	NewSevenDays   int64                 `json:"new_seven_days"`
	NewByDay       []IndexedDiscoveryDay `json:"new_by_day"`
	Brands         []IndexedBrandCount   `json:"brands,omitempty"`
	Subnets        []IndexedSubnetCount  `json:"subnets,omitempty"`
}

type IndexedDiscoveryDay struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

type IndexedBrandCount struct {
	Brand      string `json:"brand"`
	DeviceType string `json:"device_type"`
	Count      int64  `json:"count"`
}

type IndexedSubnetCount struct {
	Subnet string `json:"subnet"`
	Count  int64  `json:"count"`
}

type IndexedDeviceTypeCount struct {
	DeviceType string `json:"device_type"`
	Count      int64  `json:"count"`
}

// IndexedVLANCount counts trusted identities per VLAN inside the same filtered
// window. It is a facet for choosing filters, not a device-total breakdown.
type IndexedVLANCount struct {
	VLAN  string `json:"vlan"`
	Count int64  `json:"count"`
}

const indexedVLANFacetLimit = 100

// DevicesIndexedMetadata counts the same filtered trusted-identity groups as
// DevicesIndexed, independently of cursor/limit. Only the count is returned to
// Go; errors remain errors and are never reported as an empty inventory.
func (r Repository) DevicesIndexedMetadata(ctx context.Context, q DeviceQuery) (IndexedDeviceMetadata, error) {
	return r.devicesIndexedMetadata(ctx, r.DB, q, true)
}

func (r Repository) DevicesIndexedMetadataSnapshot(ctx context.Context, tx *sql.Tx, q DeviceQuery) (IndexedDeviceMetadata, error) {
	return r.devicesIndexedMetadata(ctx, tx, q, false)
}

func (r Repository) devicesIndexedMetadata(ctx context.Context, db indexedQueryer, q DeviceQuery, includeFreshness bool) (IndexedDeviceMetadata, error) {
	q.HardwareV2 = r.HardwareV2
	q.structured = r.HardwareV2 && structuredReadEnabled("statistics")
	if q.structured {
		if err := checkStructuredRead(ctx, db); err != nil {
			return IndexedDeviceMetadata{}, err
		}
	}
	q.includeOverview = r.HardwareV2 && includeFreshness && !q.SkipOverview
	q.includeCandidateTypes = r.HardwareV2
	q.Cursor = ""
	q.Offset = 0
	q.Limit = 50
	selection, err := buildIndexedDeviceSelection(q)
	if err != nil {
		return IndexedDeviceMetadata{}, err
	}
	result := IndexedDeviceMetadata{CountUnit: "trusted_discovery_identity", Window: indexedWindowLabel(selection.Query.Window), Types: []IndexedDeviceTypeCount{}, AsOf: time.Now().UTC()}
	if r.HardwareV2 {
		result.ClassificationVersion = "passive-hardware/v2"
	}
	counts := ` SELECT classification_status,
 CASE WHEN classification_status='identified' THEN effective_types[1]
  WHEN classification_status='candidate' AND cardinality(effective_types)=0 THEN candidate_role
  ELSE '' END device_type,
 count(*),now() FROM matched GROUP BY classification_status,device_type`
	if r.HardwareV2 {
		counts += ` UNION ALL SELECT 'ip_product',kind,count(DISTINCT identity_key),now()
 FROM matched CROSS JOIN LATERAL unnest(product_types) kind
 WHERE classification_status='candidate' GROUP BY kind`
		counts += ` UNION ALL SELECT 'vlan',vlan,n,now() FROM (SELECT vlan,count(*) n FROM matched WHERE vlan<>'' GROUP BY vlan ORDER BY count(*) DESC,vlan LIMIT 100) v`
	}
	if q.includeOverview {
		counts += indexedOverviewCountsSQL
	}
	rows, err := db.QueryContext(ctx, selection.CTE+counts+` ORDER BY 1,2`, selection.Args...)
	if err != nil {
		return IndexedDeviceMetadata{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var state, kind string
		var count int64
		var at time.Time
		if err := rows.Scan(&state, &kind, &count, &at); err != nil {
			return IndexedDeviceMetadata{}, err
		}
		if state == "vlan" {
			result.VLANs = append(result.VLANs, IndexedVLANCount{VLAN: kind, Count: count})
			continue
		}
		if state == "ip_product" {
			result.IPProductTypes = append(result.IPProductTypes, IndexedDeviceTypeCount{DeviceType: kind, Count: count})
			continue
		}
		if q.includeOverview {
			switch state {
			case "overview", "overview_day", "overview_brand", "overview_subnet":
				if result.Overview == nil {
					result.Overview = &IndexedDiscoveryOverview{NewByDay: []IndexedDiscoveryDay{}}
				}
				if err := result.Overview.add(state, kind, count); err != nil {
					return IndexedDeviceMetadata{}, err
				}
				continue
			}
		}
		result.Total += count
		result.AsOf = at
		switch state {
		case "identified":
			result.Identified += count
			result.Types = append(result.Types, IndexedDeviceTypeCount{DeviceType: kind, Count: count})
		case "candidate":
			result.Candidate += count
			if r.HardwareV2 && kind != "" {
				result.CandidateTypes = append(result.CandidateTypes, IndexedDeviceTypeCount{DeviceType: kind, Count: count})
			}
		case "conflict":
			result.Conflict += count
		case "expired":
			result.Expired += count
		}
	}
	if err := rows.Err(); err != nil {
		return IndexedDeviceMetadata{}, err
	}
	sort.SliceStable(result.VLANs, func(i, j int) bool {
		if result.VLANs[i].Count != result.VLANs[j].Count {
			return result.VLANs[i].Count > result.VLANs[j].Count
		}
		return result.VLANs[i].VLAN < result.VLANs[j].VLAN
	})
	if result.Overview != nil {
		sort.Slice(result.Overview.Brands, func(i, j int) bool {
			a, b := result.Overview.Brands[i], result.Overview.Brands[j]
			if a.Count != b.Count {
				return a.Count > b.Count
			}
			if a.Brand != b.Brand {
				return a.Brand < b.Brand
			}
			return a.DeviceType < b.DeviceType
		})
		sort.Slice(result.Overview.Subnets, func(i, j int) bool {
			a, b := result.Overview.Subnets[i], result.Overview.Subnets[j]
			if a.Count != b.Count {
				return a.Count > b.Count
			}
			return a.Subnet < b.Subnet
		})
	}
	// Report the data cutoff rather than the query time: the page prints this as
	// the statistics timestamp, and the discovery projection intentionally runs
	// one holdback behind the newest mirrored event.
	if includeFreshness {
		if fresh := r.PassiveDiscoveryFreshness(ctx); fresh != nil {
			if at, ok := fresh["cursor_at"].(time.Time); ok && !at.IsZero() {
				result.AsOf = at
			}
		}
	}
	return result, nil
}

var indexedOverviewCountsSQL = `
 UNION ALL SELECT 'overview','active',count(*),now() FROM matched WHERE last_seen>=now()-interval '15 minutes'
 UNION ALL SELECT 'overview','dumb',count(*),now() FROM matched WHERE ` + hardwareIoTAdmissionSQL() + `
 UNION ALL SELECT 'overview','previous_active',count(b.scope_key),now()
 FROM matched m LEFT JOIN passive_hardware_current h USING(identity_key)
 LEFT JOIN (
  SELECT DISTINCT b.scope_key,b.value
  FROM passive_census_identifier_5m b WHERE b.kind='mac'
   AND b.bucket_at>=date_bin(interval '5 minutes',now()-interval '24 hours 15 minutes','2000-01-01'::timestamptz)
   AND b.bucket_at<now()-interval '24 hours'
   AND ((b.first_seen>=now()-interval '24 hours 15 minutes' AND b.first_seen<now()-interval '24 hours')
     OR (b.last_seen>=now()-interval '24 hours 15 minutes' AND b.last_seen<now()-interval '24 hours'))
 ) b ON b.scope_key=h.scope_key AND b.value=h.mac
 LEFT JOIN passive_census_runtime r ON r.sensor_id=h.sensor_id AND r.last_error=''
   AND r.available_from<=now()-interval '24 hours 15 minutes' AND r.last_source_at>=now()-interval '24 hours'
   AND (r.oldest_pending_at IS NULL OR r.oldest_pending_at>=now()-interval '24 hours')
 HAVING count(*)>0 AND count(h.identity_key)=count(*) AND count(r.sensor_id)=count(*)
 UNION ALL SELECT 'overview_day',to_char(d.at,'YYYY-MM-DD'),count(m.identity_key),now()
 FROM generate_series(date_trunc('day',now() AT TIME ZONE 'Asia/Shanghai')-interval '6 days',
   date_trunc('day',now() AT TIME ZONE 'Asia/Shanghai'),interval '24 hours') d(at)
 LEFT JOIN matched m ON m.projection_first_seen>=d.at AT TIME ZONE 'Asia/Shanghai'
   AND m.projection_first_seen<(d.at+interval '24 hours') AT TIME ZONE 'Asia/Shanghai'
 GROUP BY d.at
 UNION ALL SELECT 'overview_subnet',subnet,n,now() FROM (
  SELECT s.subnet,count(*) n FROM matched CROSS JOIN LATERAL unnest(subnets) s(subnet)
  GROUP BY s.subnet ORDER BY n DESC,s.subnet LIMIT 100
 ) networks
 UNION ALL SELECT 'overview_brand',json_build_array(b.brand,b.device_type)::text,b.n,now() FROM (
  WITH grouped AS MATERIALIZED (
   SELECT lower(trim(h.data->>'manufacturer')) brand_key,min(trim(h.data->>'manufacturer')) brand,
    m.effective_types[1] device_type,count(*) n
   FROM matched m JOIN passive_hardware_current h USING(identity_key)
   WHERE m.classification_status='identified' AND trim(h.data->>'manufacturer')<>''
   GROUP BY 1,3
  ), top_brands AS (
   SELECT brand_key,min(brand) brand FROM grouped GROUP BY brand_key ORDER BY sum(n) DESC,brand_key LIMIT 10
  )
  SELECT t.brand,g.device_type,g.n FROM grouped g JOIN top_brands t USING(brand_key)
 ) b`

func (o *IndexedDiscoveryOverview) add(state, key string, count int64) error {
	switch state {
	case "overview":
		switch key {
		case "active":
			o.Active = count
		case "dumb":
			o.DumbTerminals = count
		case "previous_active":
			o.PreviousActive = &count
		}
	case "overview_day":
		o.NewByDay = append(o.NewByDay, IndexedDiscoveryDay{Date: key, Count: count})
		o.NewSevenDays += count
	case "overview_brand":
		var fields [2]string
		if err := json.Unmarshal([]byte(key), &fields); err != nil {
			return err
		}
		o.Brands = append(o.Brands, IndexedBrandCount{Brand: fields[0], DeviceType: fields[1], Count: count})
	case "overview_subnet":
		o.Subnets = append(o.Subnets, IndexedSubnetCount{Subnet: key, Count: count})
	}
	return nil
}
