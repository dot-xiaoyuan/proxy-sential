package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

type RecognitionCoverage struct {
	Known int     `json:"known"`
	Rate  float64 `json:"rate"`
}

// SourceObservability reports, per collector log kind, how many events were
// ingested and how many of them already carry a link-layer address. The
// denominator for device identification is the number of distinct devices the
// mirror can actually observe, not the number of recognised profiles.
type SourceObservability struct {
	SourceEventType    string `json:"source_event_type"`
	EventCount         int    `json:"event_count"`
	MACAttributedCount int    `json:"mac_attributed_count"`
}

type RecognitionBrandCount struct {
	Brand string `json:"brand"`
	Count int    `json:"count"`
}

type RecognitionTypeBrandCount struct {
	DeviceType string `json:"device_type"`
	Brand      string `json:"brand"`
	Count      int    `json:"count"`
}

type RecognitionUntypedReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type RecognitionModelCount struct {
	Model string `json:"model"`
	Brand string `json:"brand,omitempty"`
	Count int    `json:"count"`
}

type DeviceRecognitionSummary struct {
	BrandInferenceConflicts int                            `json:"brand_inference_conflicts"`
	BrandInferenceEnabled   bool                           `json:"brand_inference_enabled"`
	DomainWindow            string                         `json:"domain_window"`
	DomainProcessingError   string                         `json:"domain_processing_error,omitempty"`
	TotalEndpoints          int                            `json:"total_endpoints"`
	Coverage                map[string]RecognitionCoverage `json:"coverage"`
	EventCount              int                            `json:"event_count"`
	AttributedEventCount    int                            `json:"attributed_event_count"`
	EventAttributionRate    float64                        `json:"event_attribution_rate"`
	MACAttributedEventCount int                            `json:"mac_attributed_event_count"`
	MACAttributionRate      float64                        `json:"mac_attribution_rate"`
	Observability           []SourceObservability          `json:"observability"`
	TopBrands               []RecognitionBrandCount        `json:"top_brands,omitempty"`
	TopTypeBrands           []RecognitionTypeBrandCount    `json:"top_type_brands,omitempty"`
	UntypedReasons          []RecognitionUntypedReason     `json:"untyped_reasons,omitempty"`
	TopModels               []RecognitionModelCount        `json:"top_models,omitempty"`
	EcosystemMatched        int                            `json:"ecosystem_matched"`
	EcosystemAttributed     int                            `json:"ecosystem_attributed"`
	EcosystemUnattributed   int                            `json:"ecosystem_unattributed"`
	EcosystemConflicts      int                            `json:"ecosystem_conflicts"`
	DomainRuleVersion       string                         `json:"domain_rule_version,omitempty"`
	BackfillStatus          string                         `json:"backfill_status,omitempty"`
	BackfillProcessed       int                            `json:"backfill_processed"`
	AsOf                    string                         `json:"as_of"`
	Window                  string                         `json:"window"`
}

type DeviceRecognitionSummaryReader interface {
	GetDeviceRecognitionSummary(ctx context.Context, version string) (DeviceRecognitionSummary, error)
}

func coverage(known, total int) RecognitionCoverage {
	rate := 0.0
	if total > 0 {
		rate = float64(known) / float64(total)
	}
	return RecognitionCoverage{Known: known, Rate: rate}
}

func (s *DBStore) GetDeviceRecognitionSummary(ctx context.Context, version string) (DeviceRecognitionSummary, error) {
	var snapshotErr error
	ctx, snapshotErr = s.pg.domainSnapshot(ctx)
	if snapshotErr != nil {
		return DeviceRecognitionSummary{}, snapshotErr
	}
	result := DeviceRecognitionSummary{Coverage: map[string]RecognitionCoverage{}, DomainRuleVersion: version, Window: "24h", AsOf: time.Now().UTC().Format(time.RFC3339Nano)}
	active, enabled, err := s.pg.activeDomainVersion(ctx)
	if err != nil {
		return result, err
	}
	result.DomainRuleVersion = active
	version = active
	result.DomainWindow = "7d"
	result.BrandInferenceEnabled = enabled
	_ = s.pg.db.QueryRowContext(ctx, `SELECT last_error FROM domain_recognition_state WHERE singleton`).Scan(&result.DomainProcessingError)
	items, catalogAsOf, err := s.pg.endpointRecognitionCatalog(ctx)
	if err != nil {
		return result, err
	}

	result.AsOf = catalogAsOf.UTC().Format(time.RFC3339Nano)
	counts := map[string]int{}
	for _, item := range items {
		{
			for key, v := range map[string]struct {
				value string
				score float64
			}{"vendor": {item.Vendor, item.VendorConfidence}, "brand": {item.Brand, item.BrandConfidence}, "model": {item.Model, item.ModelConfidence}, "device_type": {item.DeviceType, item.DeviceTypeConfidence}, "os_family": {item.OSFamily, item.OSFamilyConfidence}} {
				if !deviceDimensionConflict(item, key) && v.value != "" && v.value != "unknown" && v.score >= .8 {
					counts[key]++
				}
			}
		}
		if item.EcosystemHint != "" && !item.EcosystemConflict {
			counts["ecosystem"]++
		}
		if item.EcosystemConflict {
			result.EcosystemConflicts++
		}
		if item.BrandInference != nil {
			if item.BrandInference.Status == "inferred" {
				counts["brand_inferred"]++
			}
			if item.BrandInference.Status == "conflict" {
				result.BrandInferenceConflicts++
			}
		}
	}
	result.TotalEndpoints = len(items)
	for _, key := range []string{"vendor", "brand", "model", "device_type", "os_family", "ecosystem", "brand_inferred"} {
		result.Coverage[key] = coverage(counts[key], result.TotalEndpoints)
	}
	untypedReasons := map[string]int{}
	for _, item := range items {
		typed := item.DeviceType != "" && item.DeviceType != "unknown" && item.DeviceTypeConfidence >= .8 && !deviceDimensionConflict(item, "device_type")
		if typed {
			continue
		}
		switch {
		case strings.EqualFold(item.OSFamily, "Apple OS") || strings.EqualFold(item.OSFamily, "iOS") || strings.EqualFold(item.OSFamily, "iPadOS") || strings.EqualFold(item.OSFamily, "macOS"):
			untypedReasons["Apple 系统线索"]++
		case item.OSFamily != "" && item.OSFamily != "unknown":
			untypedReasons["其他系统线索"]++
		case item.Brand != "" || item.Vendor != "":
			untypedReasons["仅品牌线索"]++
		default:
			untypedReasons["缺少系统与品牌线索"]++
		}
	}
	for reason, count := range untypedReasons {
		result.UntypedReasons = append(result.UntypedReasons, RecognitionUntypedReason{Reason: reason, Count: count})
	}
	sort.Slice(result.UntypedReasons, func(i, j int) bool {
		if result.UntypedReasons[i].Count == result.UntypedReasons[j].Count {
			return result.UntypedReasons[i].Reason < result.UntypedReasons[j].Reason
		}
		return result.UntypedReasons[i].Count > result.UntypedReasons[j].Count
	})
	result.TopModels = topModels(items)
	typeBrandCounts := map[[2]string]int{}
	typeTotals := map[string]int{}
	for _, item := range items {
		if item.DeviceType == "" || item.DeviceType == "unknown" || deviceDimensionConflict(item, "device_type") || item.DeviceTypeConfidence < .8 {
			continue
		}
		if item.Brand == "" || item.Brand == "unknown" || deviceDimensionConflict(item, "brand") || item.BrandConfidence < .8 {
			continue
		}
		typeBrandCounts[[2]string{item.DeviceType, item.Brand}]++
		typeTotals[item.DeviceType]++
	}
	typeBrandPairs := make([][3]any, 0, len(typeBrandCounts))
	for key, count := range typeBrandCounts {
		typeBrandPairs = append(typeBrandPairs, [3]any{key[0], key[1], count})
	}
	sort.Slice(typeBrandPairs, func(i, j int) bool {
		left, right := typeBrandPairs[i], typeBrandPairs[j]
		lt, lb, lc := left[0].(string), left[1].(string), left[2].(int)
		rt, rb, rc := right[0].(string), right[1].(string), right[2].(int)
		if typeTotals[lt] != typeTotals[rt] {
			return typeTotals[lt] > typeTotals[rt]
		}
		if lt != rt {
			return lt < rt
		}
		if lc != rc {
			return lc > rc
		}
		return lb < rb
	})
	perType := map[string]int{}
	for _, pair := range typeBrandPairs {
		deviceType, brand, count := pair[0].(string), pair[1].(string), pair[2].(int)
		if len(result.TopTypeBrands) >= 12 || perType[deviceType] >= 3 {
			continue
		}
		perType[deviceType]++
		result.TopTypeBrands = append(result.TopTypeBrands, RecognitionTypeBrandCount{DeviceType: deviceType, Brand: brand, Count: count})
	}
	brandCounts := map[string]int{}
	for _, item := range items {
		brand := item.Brand
		if brand == "" || brand == "unknown" || deviceDimensionConflict(item, "brand") || item.BrandConfidence < .8 {
			continue
		}
		brandCounts[brand]++
	}
	for brand, count := range brandCounts {
		result.TopBrands = append(result.TopBrands, RecognitionBrandCount{Brand: brand, Count: count})
	}
	sort.Slice(result.TopBrands, func(i, j int) bool {
		if result.TopBrands[i].Count == result.TopBrands[j].Count {
			return result.TopBrands[i].Brand < result.TopBrands[j].Brand
		}
		return result.TopBrands[i].Count > result.TopBrands[j].Count
	})
	if len(result.TopBrands) > 8 {
		result.TopBrands = result.TopBrands[:8]
	}
	data, err := s.ch.query(ctx, fmt.Sprintf(`SELECT count() AS event_count,countIf(endpoint_id!='') AS attributed_event_count FROM normalized_events PREWHERE timestamp>=now()-INTERVAL 24 HOUR FORMAT JSONEachRow`))
	if err != nil {
		return result, fmt.Errorf("query event attribution: %w", err)
	}
	var eventRows []struct {
		EventCount int `json:"event_count"`
		Attributed int `json:"attributed_event_count"`
	}
	if err := decodeJSONEachRow(data, &eventRows); err != nil {
		return result, err
	}
	if len(eventRows) > 0 {
		result.EventCount, result.AttributedEventCount = eventRows[0].EventCount, eventRows[0].Attributed
		if result.EventCount > 0 {
			result.EventAttributionRate = float64(result.AttributedEventCount) / float64(result.EventCount)
		}
	}
	// Per-source observability answers "how much of the mirror can identify a
	// device at all": a device identification rate is only meaningful once
	// link-layer attribution and self-report visibility are known separately.
	// A failed breakdown degrades to an empty list instead of failing the page.
	data, err = s.ch.query(ctx, `SELECT source_event_type,count() AS event_count,countIf(subject_mac!='') AS mac_attributed_count FROM normalized_events PREWHERE timestamp>=now()-INTERVAL 24 HOUR GROUP BY source_event_type ORDER BY event_count DESC LIMIT 32 FORMAT JSONEachRow`)
	if err == nil {
		var rows []struct {
			SourceEventType    string `json:"source_event_type"`
			EventCount         int    `json:"event_count"`
			MACAttributedCount int    `json:"mac_attributed_count"`
		}
		if decodeJSONEachRow(data, &rows) == nil {
			result.Observability = make([]SourceObservability, 0, len(rows))
			for _, row := range rows {
				result.Observability = append(result.Observability, SourceObservability{
					SourceEventType:    row.SourceEventType,
					EventCount:         row.EventCount,
					MACAttributedCount: row.MACAttributedCount,
				})
				result.MACAttributedEventCount += row.MACAttributedCount
			}
			if result.EventCount > 0 {
				result.MACAttributionRate = float64(result.MACAttributedEventCount) / float64(result.EventCount)
			}
		}
	}
	if version != "" {
		data, err = s.ch.query(ctx, fmt.Sprintf(`SELECT count() AS matched,countIf(attributed=1) AS attributed FROM domain_ecosystem_observations FINAL WHERE rule_version=%s AND observed_at>=now()-INTERVAL 7 DAY FORMAT JSONEachRow`, chQuote(version)))
		if err == nil {
			var domainRows []struct {
				Matched    int `json:"matched"`
				Attributed int `json:"attributed"`
			}
			if decodeJSONEachRow(data, &domainRows) == nil && len(domainRows) > 0 {
				result.EcosystemMatched, result.EcosystemAttributed = domainRows[0].Matched, domainRows[0].Attributed
			}
		}
		if progress, progressErr := s.pg.loadDomainBackfillProgress(ctx, version); progressErr == nil {
			result.BackfillStatus, result.BackfillProcessed = progress.Status, progress.Processed
			if result.EcosystemMatched == 0 {
				result.EcosystemMatched, result.EcosystemAttributed = progress.Matched, progress.Attributed
			}
		}
	}
	result.EcosystemUnattributed = result.EcosystemMatched - result.EcosystemAttributed
	if result.EcosystemUnattributed < 0 {
		result.EcosystemUnattributed = 0
	}
	return result, nil
}

func topModels(items []EndpointDeviceInventory) []RecognitionModelCount {
	counts := map[string]int{}
	brands := map[string]string{}
	for _, item := range items {
		model := strings.TrimSpace(item.Model)
		if model == "" || model == "unknown" || deviceDimensionConflict(item, "model") || item.ModelConfidence < .8 {
			continue
		}
		counts[model]++
		if brands[model] == "" && item.Brand != "" && item.Brand != "unknown" {
			brands[model] = item.Brand
		}
	}
	type entry struct {
		model, brand string
		count        int
	}
	list := make([]entry, 0, len(counts))
	for model, count := range counts {
		list = append(list, entry{model: model, brand: brands[model], count: count})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count == list[j].count {
			return list[i].model < list[j].model
		}
		return list[i].count > list[j].count
	})
	if len(list) > 8 {
		list = list[:8]
	}
	result := make([]RecognitionModelCount, 0, len(list))
	for _, item := range list {
		result = append(result, RecognitionModelCount{Model: item.model, Brand: item.brand, Count: item.count})
	}
	return result
}

