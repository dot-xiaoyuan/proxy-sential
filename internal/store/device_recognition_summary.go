package store

import (
	"context"
	"fmt"
	"time"
)

type RecognitionCoverage struct {
	Known int     `json:"known"`
	Rate  float64 `json:"rate"`
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
		if !item.RecognitionConflict {
			for key, v := range map[string]struct {
				value string
				score float64
			}{"vendor": {item.Vendor, item.VendorConfidence}, "brand": {item.Brand, item.BrandConfidence}, "model": {item.Model, item.ModelConfidence}, "device_type": {item.DeviceType, item.DeviceTypeConfidence}, "os_family": {item.OSFamily, item.OSFamilyConfidence}} {
				if v.value != "" && v.value != "unknown" && v.score >= .8 {
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
