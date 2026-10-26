package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/streamlog"
)

type preparedRiskFeature struct {
	item        preparedStreamEvent
	featureJSON string
	featureHash string
}

func prepareStreamRiskFeatures(segment streamlog.Segment) ([]preparedRiskFeature, error) {
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		return nil, err
	}
	result := make([]preparedRiskFeature, 0, len(prepared))
	for _, item := range prepared {
		if !evidence.StreamRiskFeatureEligible(item.event) {
			continue
		}
		encoded, err := json.Marshal(evidence.FeatureEvent(item.event))
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(encoded)
		result = append(result, preparedRiskFeature{item: item, featureJSON: string(encoded), featureHash: hex.EncodeToString(hash[:])})
	}
	return result, nil
}

// WriteStreamRiskFeatures is a separate confirmed write from the search row.
// A feature is never substituted for an authoritative event body.
func (s *ClickHouseStore) WriteStreamRiskFeatures(ctx context.Context, segmentID string, segment streamlog.Segment) error {
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil || len(features) == 0 {
		return err
	}
	month, _ := strconv.ParseUint(segment.ArchiveMonth, 10, 32)
	var body bytes.Buffer
	body.WriteString("INSERT INTO stream_risk_features_v1 FORMAT JSONEachRow\n")
	for _, feature := range features {
		item := feature.item
		row := map[string]any{
			"archive_month": month, "scope_id": item.scope, "event_key": item.key,
			"content_sha256": item.hash, "feature_sha256": feature.featureHash,
			"feature_version": evidence.FeatureEventVersion,
			"accepted_at":     segment.AcceptedAt.UTC().Format("2006-01-02 15:04:05.000000"),
			"observed_at":     item.observed.Format("2006-01-02 15:04:05.000000"),
			"sensor_id":       stringFromMap(item.event.Observer, "sensor_id"),
			"subject_ip":      stringFromMap(item.event.Subject, "ip"),
			"account_id":      stringFromMap(item.event.Subject, "account_id"),
			"event_type":      item.event.Type, "feature_json": feature.featureJSON,
		}
		if err := writeJSONLine(&body, row); err != nil {
			return err
		}
	}
	_, err = s.queryWithSettings(ctx, body.String(), streamInsertSettings(segmentID, "stream_risk_features_v1"))
	return err
}

// VerifyStreamRiskFeatures is used only after an unknown insert result. It
// compares the fixed body key and the rule-specific feature hash in one bounded
// source segment; a same-key different-content row is a hard conflict.
func (s *ClickHouseStore) VerifyStreamRiskFeatures(ctx context.Context, segment streamlog.Segment) (bool, error) {
	missing, err := s.missingStreamRiskFeatures(ctx, segment)
	if err != nil {
		return false, err
	}
	return len(missing) == 0, nil
}

func (s *ClickHouseStore) missingStreamRiskFeatures(ctx context.Context, segment streamlog.Segment) ([]int, error) {
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil || len(features) == 0 {
		return nil, err
	}
	keys := make([]string, 0, len(features))
	expected := make(map[string]int, len(features))
	minTime, maxTime := features[0].item.observed, features[0].item.observed
	for index, feature := range features {
		item := feature.item
		keys = append(keys, "("+chQuote(item.scope)+","+chQuote(item.key)+")")
		expected[item.scope+"\x00"+item.key] = index
		if item.observed.Before(minTime) {
			minTime = item.observed
		}
		if item.observed.After(maxTime) {
			maxTime = item.observed
		}
	}
	query := "SELECT scope_id,event_key,content_sha256,feature_sha256,feature_version,archive_month FROM stream_risk_features_v1 WHERE observed_at >= " +
		chQuote(minTime.Format("2006-01-02 15:04:05.000000")) + " AND observed_at <= " + chQuote(maxTime.Format("2006-01-02 15:04:05.000000")) +
		" AND (scope_id,event_key) IN (" + strings.Join(keys, ",") + ") FORMAT JSONEachRow"
	data, err := s.query(ctx, query)
	if err != nil {
		return nil, err
	}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			Scope       string `json:"scope_id"`
			Key         string `json:"event_key"`
			ContentHash string `json:"content_sha256"`
			FeatureHash string `json:"feature_sha256"`
			Version     string `json:"feature_version"`
			Month       uint32 `json:"archive_month"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, err
		}
		key := row.Scope + "\x00" + row.Key
		index, found := expected[key]
		feature := features[index]
		if !found || row.ContentHash != feature.item.hash || row.FeatureHash != feature.featureHash ||
			row.Version != evidence.FeatureEventVersion || fmt.Sprint(row.Month) != segment.ArchiveMonth {
			return nil, streamlog.ErrContentConflict
		}
		delete(expected, key)
	}
	missing := make([]int, 0, len(expected))
	for _, index := range expected {
		missing = append(missing, index)
	}
	return missing, nil
}
