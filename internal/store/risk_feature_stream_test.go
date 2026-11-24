package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestRiskFeatureStreamReadsHotSubjectInOneResponse(t *testing.T) {
	segment := riskFeatureTestSegment()
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil {
		t.Fatal(err)
	}
	feature := features[0]
	base := map[string]any{"scope_id": feature.item.scope, "event_key": feature.item.key,
		"content_sha256": feature.item.hash, "feature_sha256": feature.featureHash,
		"feature_version": "risk-features-v1", "feature_json": feature.featureJSON,
		"sensor_id": "sensor-a", "subject_ip": "192.0.2.8", "account_id": "account-a",
		"observed_at": segment.AcceptedAt.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")}
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		queries = append(queries, query)
		for range 3 { // identical physical rows may exceed one ClickHouse block
			encoded, _ := json.Marshal(base)
			_, _ = w.Write(append(encoded, '\n'))
			w.(http.Flusher).Flush()
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	claims := []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8"}}
	seen := 0
	count, err := ch.StreamRiskFeatureEvents(context.Background(), "sensor-a", claims,
		segment.AcceptedAt.Add(-time.Minute), segment.AcceptedAt.Add(time.Minute), segment.AcceptedAt.Add(-time.Minute), 2,
		func(event normalized.Event) error { seen++; return nil })
	if err != nil || count != 1 || seen != 1 || len(queries) != 1 {
		t.Fatalf("stream lost or repeated an event: count=%d seen=%d queries=%d err=%v", count, seen, len(queries), err)
	}
	query := queries[0]
	if strings.Contains(query, "stream_event_body") || strings.Contains(query, "SHA256(feature_json)") ||
		!strings.Contains(query, "LIMIT 200001") || !strings.Contains(query, "max_block_size=2") || !strings.Contains(query, "accepted_at<=") {
		t.Fatalf("unbounded or non-frozen risk read: %s", query)
	}
}

func TestRiskFeatureStreamRejectsConflictAcrossResponseBlocks(t *testing.T) {
	segment := riskFeatureTestSegment()
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil {
		t.Fatal(err)
	}
	feature := features[0]
	base := map[string]any{"scope_id": feature.item.scope, "event_key": feature.item.key,
		"content_sha256": feature.item.hash, "feature_sha256": feature.featureHash,
		"feature_version": "risk-features-v1", "feature_json": feature.featureJSON,
		"sensor_id": "sensor-a", "subject_ip": "192.0.2.8", "account_id": "account-a",
		"observed_at": segment.AcceptedAt.UTC().Format("2006-01-02 15:04:05.000000")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encoded, _ := json.Marshal(base)
		_, _ = fmt.Fprintln(w, string(encoded))
		w.(http.Flusher).Flush()
		base["content_sha256"] = strings.Repeat("f", 64)
		encoded, _ = json.Marshal(base)
		_, _ = fmt.Fprintln(w, string(encoded))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	claims := []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8"}}
	_, err = ch.StreamRiskFeatureEvents(context.Background(), "sensor-a", claims,
		segment.AcceptedAt.Add(-time.Minute), segment.AcceptedAt.Add(time.Minute), segment.AcceptedAt.Add(-time.Minute), 1,
		func(normalized.Event) error { return nil })
	if err != streamlog.ErrContentConflict {
		t.Fatalf("cross-block same-key conflict not rejected: %v", err)
	}
}

func TestRiskFeatureReadRejectsUnfinishedResponses(t *testing.T) {
	for _, tt := range []struct {
		name      string
		limit     int64
		serve     http.HandlerFunc
		want      error
		wantError string
	}{
		{name: "over byte limit", limit: 3, serve: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "{}\n{}\n")
		}, want: ErrRiskFeatureStreamBound},
		{name: "server result limit after a row", limit: 4096, serve: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "{}\n")
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "\nCode: 396. DB::Exception: Limit for result exceeded\n")
		}, want: ErrRiskFeatureStreamBound},
		{name: "exception header on success status", limit: 4096, serve: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-ClickHouse-Exception-Code", "210")
		}, wantError: "exception code 210"},
		{name: "exception trailer after a row", limit: 4096, serve: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Trailer", "X-ClickHouse-Exception-Code")
			_, _ = io.WriteString(w, "{}\n")
			w.(http.Flusher).Flush()
			w.Header().Set("X-ClickHouse-Exception-Code", "396")
		}, want: ErrRiskFeatureStreamBound},
		{name: "truncated HTTP body", limit: 4096, serve: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "12")
			_, _ = io.WriteString(w, "{}\n")
		}, want: io.ErrUnexpectedEOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serve)
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ch.scanRiskFeatureRows(context.Background(), "SELECT 1", tt.limit, func([]byte) error { return nil })
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) ||
				(tt.wantError != "" && !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("unfinished response returned %v, want %v %q", err, tt.want, tt.wantError)
			}
		})
	}
}
