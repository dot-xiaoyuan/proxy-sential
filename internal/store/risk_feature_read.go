package store

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

var ErrRiskFeatureStreamBound = errors.New("risk feature stream exceeded bounded group size")

const (
	maxRiskFeaturePhysicalRows  = 200000
	maxRiskFeaturePhysicalBytes = 128 << 20
	maxRiskFeatureDistinctRows  = 100000
	maxRiskFeatureDistinctBytes = 64 << 20
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

// StreamRiskFeatureEvents reads a fixed accepted-time snapshot once per
// selection and decodes it as it arrives. The physical bounds apply across
// both selections and every version of the same logical event is verified.
func (s *ClickHouseStore) StreamRiskFeatureEvents(ctx context.Context, sensor string, subjects []RiskSubjectClaim, from, to, acceptedAfter time.Time, blockSize int, emit func(normalized.Event) error) (int, error) {
	if s == nil || sensor == "" || len(subjects) == 0 || len(subjects) > maxRiskSubjectClaim ||
		from.IsZero() || !from.Before(to) || acceptedAfter.IsZero() || acceptedAfter.After(to) ||
		blockSize < 1 || blockSize > 5000 || emit == nil {
		return 0, errors.New("invalid streaming risk feature query")
	}
	ipSet, accountSet := map[string]bool{}, map[string]bool{}
	for _, subject := range subjects {
		if subject.SensorID != sensor || subject.ID == "" {
			return 0, errors.New("risk subject scope mismatch")
		}
		switch subject.Type {
		case "ip":
			ipSet[subject.ID] = true
		case "account":
			accountSet[subject.ID] = true
		default:
			return 0, errors.New("unknown risk subject type")
		}
	}
	selections := make([]string, 0, 2)
	for _, item := range []struct {
		column string
		set    map[string]bool
	}{{"subject_ip", ipSet}, {"account_id", accountSet}} {
		if len(item.set) == 0 {
			continue
		}
		values := make([]string, 0, len(item.set))
		for value := range item.set {
			values = append(values, chQuote(value))
		}
		sort.Strings(values)
		selections = append(selections, item.column+" IN ("+strings.Join(values, ",")+")")
	}
	type featureRow struct {
		Scope       string `json:"scope_id"`
		Key         string `json:"event_key"`
		ContentHash string `json:"content_sha256"`
		FeatureHash string `json:"feature_sha256"`
		Version     string `json:"feature_version"`
		FeatureJSON string `json:"feature_json"`
		Sensor      string `json:"sensor_id"`
		IP          string `json:"subject_ip"`
		Account     string `json:"account_id"`
		ObservedAt  string `json:"observed_at"`
	}
	seen := map[string]string{}
	count := 0
	physicalRows, distinctBytes := 0, 0
	var physicalBytes int64
	for _, selection := range selections {
		// The extra row distinguishes a complete result at the limit from one
		// with more work. Nothing is committed until both streams have succeeded.
		rowLimit := maxRiskFeaturePhysicalRows - physicalRows + 1
		byteLimit := maxRiskFeaturePhysicalBytes - physicalBytes
		query := fmt.Sprintf(`SELECT scope_id,event_key,content_sha256,feature_sha256,feature_version,feature_json,sensor_id,subject_ip,account_id,observed_at
FROM stream_risk_features_v1 WHERE sensor_id=%s AND observed_at>=%s AND observed_at<=%s AND accepted_at>=%s AND accepted_at<=%s AND feature_version=%s AND %s
ORDER BY observed_at,event_key,scope_id,content_sha256,feature_sha256,subject_ip,account_id LIMIT %d
SETTINGS max_threads=1,max_execution_time=3,max_block_size=%d,max_result_rows=%d,max_result_bytes=%d,result_overflow_mode='throw',http_write_exception_in_output_format=0 FORMAT JSONEachRow`,
			chQuote(sensor), chQuote(from.UTC().Format("2006-01-02 15:04:05.000000")),
			chQuote(to.UTC().Format("2006-01-02 15:04:05.000000")), chQuote(acceptedAfter.UTC().Format("2006-01-02 15:04:05.000000")),
			chQuote(to.UTC().Format("2006-01-02 15:04:05.000000")), chQuote(evidence.FeatureEventVersion), selection,
			rowLimit, blockSize, rowLimit, max(1, byteLimit))
		used, err := s.scanRiskFeatureRows(ctx, query, byteLimit, func(line []byte) error {
			physicalRows++
			if physicalRows > maxRiskFeaturePhysicalRows {
				return ErrRiskFeatureStreamBound
			}
			var row featureRow
			if err := json.Unmarshal(line, &row); err != nil {
				return err
			}
			observedAt, err := streamSearchObservedAt(row.ObservedAt)
			if err != nil || !isCanonicalClickHouseMicrosecond(row.ObservedAt, observedAt) {
				return streamlog.ErrContentConflict
			}
			hash := sha256.Sum256([]byte(row.FeatureJSON))
			if row.Scope == "" || row.Key == "" || row.Sensor != sensor || row.Version != evidence.FeatureEventVersion ||
				row.ContentHash == "" || row.FeatureHash != hex.EncodeToString(hash[:]) {
				return streamlog.ErrContentConflict
			}
			identity := row.Scope + "\x00" + row.Key
			content := row.ContentHash + "\x00" + row.FeatureHash
			if previous, exists := seen[identity]; exists {
				if previous != content {
					return streamlog.ErrContentConflict
				}
				return nil
			}
			seen[identity] = content
			distinctBytes += len(row.FeatureJSON)
			if count+1 > maxRiskFeatureDistinctRows || distinctBytes > maxRiskFeatureDistinctBytes {
				return ErrRiskFeatureStreamBound
			}
			var event normalized.Event
			if err := json.Unmarshal([]byte(row.FeatureJSON), &event); err != nil {
				return err
			}
			if event.EventID == "" || event.Timestamp == "" || stringFromMap(event.Subject, "ip") != row.IP ||
				stringFromMap(event.Subject, "account_id") != row.Account {
				return streamlog.ErrContentConflict
			}
			if event.Observer == nil {
				event.Observer = map[string]any{}
			}
			event.Observer["sensor_id"] = sensor
			if err := emit(event); err != nil {
				return err
			}
			count++
			return nil
		})
		if err != nil {
			return count, err
		}
		physicalBytes += used
	}
	return count, nil
}

func (s *ClickHouseStore) scanRiskFeatureRows(ctx context.Context, query string, byteLimit int64, emit func([]byte) error) (int64, error) {
	resp, err := s.openQueryResponse(ctx, query, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	const exceptionHeader = "X-ClickHouse-Exception-Code"
	if err := riskFeatureHTTPException(resp.Header.Get(exceptionHeader)); err != nil {
		return 0, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return 0, err
		}
		if bytes.HasPrefix(bytes.TrimSpace(detail), []byte("Code: 396.")) {
			return 0, ErrRiskFeatureStreamBound
		}
		return 0, fmt.Errorf("clickhouse risk feature query failed: status=%d body=%s", resp.StatusCode, bytes.TrimSpace(detail))
	}
	reader := &io.LimitedReader{R: resp.Body, N: byteLimit + 1}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 16<<10), int(byteLimit)+1)
	for scanner.Scan() {
		if reader.N == 0 {
			return 0, ErrRiskFeatureStreamBound
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// ClickHouse may append an exception after sending an HTTP 200 and
		// one or more rows. Never treat those partial results as complete.
		if bytes.HasPrefix(line, []byte("Code: 396.")) {
			return 0, ErrRiskFeatureStreamBound
		}
		if err := emit(line); err != nil {
			return 0, err
		}
	}
	if reader.N == 0 {
		return 0, ErrRiskFeatureStreamBound
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return byteLimit + 1 - reader.N, riskFeatureHTTPException(resp.Trailer.Get(exceptionHeader))
}

func riskFeatureHTTPException(code string) error {
	switch code {
	case "", "0":
		return nil
	case "396": // TOO_MANY_ROWS_OR_BYTES
		return ErrRiskFeatureStreamBound
	default:
		return fmt.Errorf("clickhouse risk feature query failed: exception code %s", code)
	}
}
