package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type AttributionDiagnostic struct {
	EventID           string  `json:"event_id"`
	ObservedAt        string  `json:"observed_at"`
	SensorID          string  `json:"sensor_id"`
	IP                string  `json:"ip,omitempty"`
	EndpointID        string  `json:"endpoint_id,omitempty"`
	Domain            string  `json:"domain"`
	Ecosystem         string  `json:"ecosystem"`
	RuleVersion       string  `json:"rule_version"`
	AttributionMethod string  `json:"attribution_method,omitempty"`
	Reason            string  `json:"reason"`
	Attributed        bool    `json:"attributed"`
	Confidence        float64 `json:"confidence"`
}

type AttributionDiagnosticQuery struct {
	From, To, SensorID, Status, Reason, RuleVersion string
	Limit, Offset                                   int
}

type AttributionDiagnosticPage struct {
	Items []AttributionDiagnostic `json:"items"`
	Total int                     `json:"total"`
}

type AttributionDiagnosticReader interface {
	ListAttributionDiagnostics(context.Context, AttributionDiagnosticQuery) (AttributionDiagnosticPage, error)
}

type AttributionVersionStats struct {
	RuleVersion string  `json:"rule_version"`
	Total       int     `json:"total"`
	Attributed  int     `json:"attributed"`
	Conflicts   int     `json:"conflicts"`
	Rate        float64 `json:"rate"`
}

type AttributionComparison struct {
	From   string                  `json:"from"`
	To     string                  `json:"to"`
	Before AttributionVersionStats `json:"before"`
	After  AttributionVersionStats `json:"after"`
}

type AttributionComparisonReader interface {
	CompareAttributionVersions(context.Context, string, string, string, string, string) (AttributionComparison, error)
}

func (s *DBStore) CompareAttributionVersions(ctx context.Context, from, to, sensorID, before, after string) (AttributionComparison, error) {
	return s.ch.CompareAttributionVersions(ctx, from, to, sensorID, before, after)
}

func (s *ClickHouseStore) CompareAttributionVersions(ctx context.Context, from, to, sensorID, before, after string) (AttributionComparison, error) {
	start, err := time.Parse(time.RFC3339, from)
	if err != nil {
		return AttributionComparison{}, fmt.Errorf("invalid from: %w", err)
	}
	end, err := time.Parse(time.RFC3339, to)
	if err != nil || !end.After(start) || end.Sub(start) > 30*24*time.Hour {
		return AttributionComparison{}, fmt.Errorf("invalid attribution comparison window")
	}
	if before == "" || after == "" || before == after {
		return AttributionComparison{}, fmt.Errorf("two distinct rule versions are required")
	}
	where := "observed_at>=parseDateTime64BestEffort(" + chQuote(start.UTC().Format(time.RFC3339Nano)) + ",6,'UTC') AND observed_at<parseDateTime64BestEffort(" + chQuote(end.UTC().Format(time.RFC3339Nano)) + ",6,'UTC')"
	if sensorID != "" {
		where += " AND sensor_id=" + chQuote(sensorID)
	}
	where += " AND rule_version IN (" + chQuote(before) + "," + chQuote(after) + ")"
	common := "(event_id,ecosystem) IN (SELECT event_id,ecosystem FROM domain_ecosystem_observations FINAL WHERE " + where + " GROUP BY event_id,ecosystem HAVING uniqExact(rule_version)=2)"
	data, err := s.query(ctx, "SELECT rule_version,count() AS total,sum(attributed) AS attributed,countIf(attribution_reason='identity_conflict') AS conflicts FROM domain_ecosystem_observations FINAL WHERE "+where+" AND "+common+" GROUP BY rule_version FORMAT JSONEachRow")
	if err != nil {
		return AttributionComparison{}, err
	}
	var rows []AttributionVersionStats
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return AttributionComparison{}, err
	}
	result := AttributionComparison{From: start.UTC().Format(time.RFC3339), To: end.UTC().Format(time.RFC3339), Before: AttributionVersionStats{RuleVersion: before}, After: AttributionVersionStats{RuleVersion: after}}
	for _, row := range rows {
		if row.Total > 0 {
			row.Rate = float64(row.Attributed) / float64(row.Total)
		}
		if row.RuleVersion == before {
			result.Before = row
		} else if row.RuleVersion == after {
			result.After = row
		}
	}
	if result.Before.Total == 0 || result.After.Total == 0 {
		return AttributionComparison{}, fmt.Errorf("both rule versions need observations in the selected window")
	}
	return result, nil
}

func (s *DBStore) ListAttributionDiagnostics(ctx context.Context, query AttributionDiagnosticQuery) (AttributionDiagnosticPage, error) {
	return s.ch.ListAttributionDiagnostics(ctx, query)
}

func (s *ClickHouseStore) ListAttributionDiagnostics(ctx context.Context, query AttributionDiagnosticQuery) (AttributionDiagnosticPage, error) {
	from, err := time.Parse(time.RFC3339, query.From)
	if err != nil {
		return AttributionDiagnosticPage{}, fmt.Errorf("invalid from: %w", err)
	}
	to, err := time.Parse(time.RFC3339, query.To)
	if err != nil || !to.After(from) || to.Sub(from) > 30*24*time.Hour {
		return AttributionDiagnosticPage{}, fmt.Errorf("invalid attribution diagnostics window")
	}
	if query.Limit < 1 || query.Limit > 50 || query.Offset < 0 {
		return AttributionDiagnosticPage{}, fmt.Errorf("invalid attribution diagnostics page")
	}
	clauses := []string{
		"observed_at >= parseDateTime64BestEffort(" + chQuote(from.UTC().Format(time.RFC3339Nano)) + ",6,'UTC')",
		"observed_at < parseDateTime64BestEffort(" + chQuote(to.UTC().Format(time.RFC3339Nano)) + ",6,'UTC')",
	}
	if query.SensorID != "" {
		clauses = append(clauses, "sensor_id="+chQuote(query.SensorID))
	}
	if query.RuleVersion != "" {
		clauses = append(clauses, "rule_version="+chQuote(query.RuleVersion))
	}
	switch query.Status {
	case "attributed":
		clauses = append(clauses, "attributed=1")
	case "unattributed":
		clauses = append(clauses, "attributed=0")
	case "", "all":
	default:
		return AttributionDiagnosticPage{}, fmt.Errorf("invalid attribution status")
	}
	if query.Reason != "" {
		if query.Reason == "legacy_unknown" {
			clauses = append(clauses, "attribution_reason IN ('','legacy_unknown')")
		} else {
			clauses = append(clauses, "attribution_reason="+chQuote(query.Reason))
		}
	}
	where := strings.Join(clauses, " AND ")
	data, err := s.query(ctx, "SELECT count() AS total FROM domain_ecosystem_observations FINAL WHERE "+where+" FORMAT JSONEachRow")
	if err != nil {
		return AttributionDiagnosticPage{}, err
	}
	var totals []struct {
		Total int `json:"total"`
	}
	if err := decodeJSONEachRow(data, &totals); err != nil {
		return AttributionDiagnosticPage{}, err
	}
	page := AttributionDiagnosticPage{Items: []AttributionDiagnostic{}}
	if len(totals) > 0 {
		page.Total = totals[0].Total
	}
	data, err = s.query(ctx, fmt.Sprintf(`SELECT event_id,formatDateTime(raw_observed_at,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS observed_at,sensor_id,subject_ip AS ip,endpoint_id,domain,ecosystem,rule_version,attribution_method,if(attribution_reason='','legacy_unknown',attribution_reason) AS reason,toBool(attributed) AS attributed,confidence FROM (SELECT observed_at AS raw_observed_at,event_id,sensor_id,subject_ip,endpoint_id,domain,ecosystem,rule_version,attribution_method,attribution_reason,attributed,confidence FROM domain_ecosystem_observations FINAL WHERE %s ORDER BY observed_at DESC,event_id DESC LIMIT %d OFFSET %d) FORMAT JSONEachRow`, where, query.Limit, query.Offset))
	if err != nil {
		return AttributionDiagnosticPage{}, err
	}
	if err := decodeJSONEachRow(data, &page.Items); err != nil {
		return AttributionDiagnosticPage{}, err
	}
	return page, nil
}
