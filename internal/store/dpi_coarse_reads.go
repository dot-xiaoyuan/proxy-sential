package store

import (
	"context"
	"fmt"
)

func (s *ClickHouseStore) queryDPICoarseOverview(ctx context.Context, query ActivityQuery) (DPIOverview, error) {
	window, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return DPIOverview{}, err
	}
	source, err := activityChartFactRowsSQL(query, duration, []string{"type", "source_ip", "protocol_label"})
	if err != nil {
		return DPIOverview{}, err
	}
	raw, err := s.activityFeatureQuery(ctx, fmt.Sprintf(`SELECT sumIf(event_count,dimension='type') AS event_count,uniqExactIf(value,dimension='source_ip' AND value!='') AS active_ip_count,uniqExactIf(value,dimension='protocol_label' AND value!='') AS protocol_flow_count,minOrNullIf(first_seen,dimension='type') AS first_seen,maxOrNullIf(last_seen,dimension='type') AS last_seen FROM(%s) FORMAT JSONEachRow`, source))
	if err != nil {
		return DPIOverview{}, err
	}
	var summaries []struct {
		EventCount        int     `json:"event_count"`
		ActiveIPCount     int     `json:"active_ip_count"`
		ProtocolFlowCount int     `json:"protocol_flow_count"`
		FirstSeen         *string `json:"first_seen"`
		LastSeen          *string `json:"last_seen"`
	}
	if err = decodeJSONEachRow(raw, &summaries); err != nil {
		return DPIOverview{}, err
	}
	result := DPIOverview{SensorID: query.SensorID, Window: window}
	if len(summaries) > 0 {
		summary := summaries[0]
		result.EventCount = summary.EventCount
		result.FlowSampleCount = summary.EventCount
		result.ActiveIPCount = summary.ActiveIPCount
		result.ProtocolFlowCount = summary.ProtocolFlowCount
		if summary.FirstSeen != nil {
			result.FirstSeen = normalizeClickHouseTimestamp(*summary.FirstSeen)
		}
		if summary.LastSeen != nil {
			result.LastSeen = normalizeClickHouseTimestamp(*summary.LastSeen)
		}
	}
	source, err = activityChartFactRowsSQL(query, duration, []string{"ip_ja3", "ip_ja4", "ip_ttl"})
	if err != nil {
		return DPIOverview{}, err
	}
	raw, err = s.activityFeatureQuery(ctx, fmt.Sprintf(`SELECT sum(toUInt8(length(ja3s)+length(ja4s)>1)+toUInt8(length(ttls)>1)) AS count FROM(SELECT groupUniqArrayIf(8)(JSONExtractString(p.value,2),dimension='ip_ja3') AS ja3s,groupUniqArrayIf(8)(JSONExtractString(p.value,2),dimension='ip_ja4') AS ja4s,groupUniqArrayIf(8)(JSONExtractString(p.value,2),dimension='ip_ttl') AS ttls FROM(%s) AS p GROUP BY JSONExtractString(p.value,1)) FORMAT JSONEachRow`, source))
	if err != nil {
		return DPIOverview{}, err
	}
	result.FingerprintConflictCount, err = decodeSingleCount(raw)
	return result, err
}
