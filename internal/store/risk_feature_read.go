package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

// ListStreamRiskFeatureEvents reads only affected subjects from a bounded
// observation window. It never selects the authoritative body JSON.
func (s *ClickHouseStore) ListStreamRiskFeatureEvents(ctx context.Context, sensor string, subjects []RiskSubjectClaim, from, to, acceptedAfter time.Time, limit int) ([]normalized.Event, error) {
	if s == nil || sensor == "" || len(subjects) == 0 || len(subjects) > maxRiskSubjectClaim ||
		from.IsZero() || !from.Before(to) || acceptedAfter.IsZero() || acceptedAfter.After(to) || limit < 1 || limit > 20000 {
		return nil, errors.New("invalid incremental risk feature query")
	}
	ipSet, accountSet := map[string]bool{}, map[string]bool{}
	for _, subject := range subjects {
		if subject.SensorID != sensor || subject.ID == "" {
			return nil, errors.New("risk subject scope mismatch")
		}
		switch subject.Type {
		case "ip":
			ipSet[subject.ID] = true
		case "account":
			accountSet[subject.ID] = true
		default:
			return nil, errors.New("unknown risk subject type")
		}
	}
	selections := make([]string, 0, 2)
	for _, item := range []struct {
		column string
		set    map[string]bool
	}{{"subject_ip", ipSet}, {"account_id", accountSet}} {
		column, set := item.column, item.set
		if len(set) == 0 {
			continue
		}
		values := make([]string, 0, len(set))
		for value := range set {
			values = append(values, chQuote(value))
		}
		sort.Strings(values)
		selections = append(selections, column+" IN ("+strings.Join(values, ",")+")")
	}
	result := make([]normalized.Event, 0)
	seen := map[string]string{}
	physicalRows := 0
	// An OR between the IP primary order and the account skip index can force
	// an unnecessarily broad scan. Each bounded lookup uses its own index.
	for _, selection := range selections {
		query := fmt.Sprintf(`SELECT scope_id,event_key,content_sha256,feature_sha256,feature_version,feature_json,sensor_id,subject_ip,account_id,observed_at
FROM stream_risk_features_v1 WHERE sensor_id=%s AND observed_at>=%s AND observed_at<=%s AND accepted_at>=%s AND feature_version=%s AND %s
ORDER BY observed_at,event_key LIMIT %d SETTINGS max_threads=1,max_execution_time=3 FORMAT JSONEachRow`,
			chQuote(sensor), chQuote(from.UTC().Format("2006-01-02 15:04:05.000000")),
			chQuote(to.UTC().Format("2006-01-02 15:04:05.000000")), chQuote(acceptedAfter.UTC().Format("2006-01-02 15:04:05.000000")), chQuote(evidence.FeatureEventVersion),
			selection, limit+1)
		data, err := s.query(ctx, query)
		if err != nil {
			return nil, err
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			physicalRows++
			if physicalRows > 2*limit {
				return nil, fmt.Errorf("risk feature query exceeded bounded physical row limit %d", 2*limit)
			}
			var row struct {
				Scope       string `json:"scope_id"`
				Key         string `json:"event_key"`
				ContentHash string `json:"content_sha256"`
				FeatureHash string `json:"feature_sha256"`
				Version     string `json:"feature_version"`
				FeatureJSON string `json:"feature_json"`
				Sensor      string `json:"sensor_id"`
				IP          string `json:"subject_ip"`
				Account     string `json:"account_id"`
			}
			if err := json.Unmarshal(line, &row); err != nil {
				return nil, err
			}
			hash := sha256.Sum256([]byte(row.FeatureJSON))
			if row.Scope == "" || row.Key == "" || row.Sensor != sensor || row.Version != evidence.FeatureEventVersion ||
				row.ContentHash == "" || row.FeatureHash != hex.EncodeToString(hash[:]) {
				return nil, streamlog.ErrContentConflict
			}
			identity := row.Scope + "\x00" + row.Key
			content := row.ContentHash + "\x00" + row.FeatureHash
			if previous, exists := seen[identity]; exists {
				if previous != content {
					return nil, streamlog.ErrContentConflict
				}
				continue
			}
			seen[identity] = content
			var event normalized.Event
			if err := json.Unmarshal([]byte(row.FeatureJSON), &event); err != nil {
				return nil, err
			}
			if event.EventID == "" || event.Timestamp == "" || stringFromMap(event.Subject, "ip") != row.IP ||
				stringFromMap(event.Subject, "account_id") != row.Account {
				return nil, streamlog.ErrContentConflict
			}
			if event.Observer == nil {
				event.Observer = map[string]any{}
			}
			event.Observer["sensor_id"] = sensor
			result = append(result, event)
			if len(result) > limit {
				return nil, fmt.Errorf("risk feature query exceeded bounded distinct row limit %d", limit)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Timestamp != result[j].Timestamp {
			return result[i].Timestamp < result[j].Timestamp
		}
		return result[i].EventID < result[j].EventID
	})
	return result, nil
}
