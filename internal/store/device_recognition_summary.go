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
	TotalEndpoints        int                            `json:"total_endpoints"`
	Coverage              map[string]RecognitionCoverage `json:"coverage"`
	EventCount            int                            `json:"event_count"`
	AttributedEventCount  int                            `json:"attributed_event_count"`
	EventAttributionRate  float64                        `json:"event_attribution_rate"`
	EcosystemMatched      int                            `json:"ecosystem_matched"`
	EcosystemAttributed   int                            `json:"ecosystem_attributed"`
	EcosystemUnattributed int                            `json:"ecosystem_unattributed"`
	EcosystemConflicts    int                            `json:"ecosystem_conflicts"`
	DomainRuleVersion     string                         `json:"domain_rule_version,omitempty"`
	BackfillStatus        string                         `json:"backfill_status,omitempty"`
	BackfillProcessed     int                            `json:"backfill_processed"`
	AsOf                  string                         `json:"as_of"`
	Window                string                         `json:"window"`
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
	result := DeviceRecognitionSummary{Coverage: map[string]RecognitionCoverage{}, DomainRuleVersion: version, Window: "24h", AsOf: time.Now().UTC().Format(time.RFC3339Nano)}
	var vendor, brand, model, deviceType, osFamily, ecosystem int
	err := s.pg.db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER (WHERE vendor IS NOT NULL AND vendor<>''),count(*) FILTER (WHERE brand IS NOT NULL AND brand<>'' AND brand_confidence>=0.8 AND NOT recognition_conflict),count(*) FILTER (WHERE model IS NOT NULL AND model<>'' AND model_confidence>=0.8 AND NOT recognition_conflict),count(*) FILTER (WHERE device_type IS NOT NULL AND device_type<>'' AND device_type_confidence>=0.8 AND NOT recognition_conflict),count(*) FILTER (WHERE os_family IS NOT NULL AND os_family<>'' AND os_family_confidence>=0.8 AND NOT recognition_conflict),count(*) FILTER (WHERE ecosystem_hint IS NOT NULL AND ecosystem_hint<>'' AND ecosystem_confidence>=0.55 AND NOT ecosystem_conflict),count(*) FILTER (WHERE ecosystem_conflict) FROM endpoint_device_profiles`).Scan(&result.TotalEndpoints, &vendor, &brand, &model, &deviceType, &osFamily, &ecosystem, &result.EcosystemConflicts)
	if err != nil {
		return result, fmt.Errorf("query recognition coverage: %w", err)
	}
	result.Coverage["vendor"] = coverage(vendor, result.TotalEndpoints)
	result.Coverage["brand"] = coverage(brand, result.TotalEndpoints)
	result.Coverage["model"] = coverage(model, result.TotalEndpoints)
	result.Coverage["device_type"] = coverage(deviceType, result.TotalEndpoints)
	result.Coverage["os_family"] = coverage(osFamily, result.TotalEndpoints)
	result.Coverage["ecosystem"] = coverage(ecosystem, result.TotalEndpoints)
	data, err := s.ch.query(ctx, fmt.Sprintf(`SELECT count() AS event_count,countIf(endpoint_id!='') AS attributed_event_count FROM normalized_events_canonical FINAL PREWHERE timestamp>=now()-INTERVAL 24 HOUR FORMAT JSONEachRow`))
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
