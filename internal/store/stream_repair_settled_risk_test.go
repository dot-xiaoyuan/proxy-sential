package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/streamlog"
)

func settledPacketRiskFixture(t *testing.T) (streamlog.Segment, []preparedStreamEvent, []preparedRiskFeature) {
	t.Helper()
	segment := testStreamSegment()
	segment.Source = "device-signals"
	segment.SourcePath = "/signals/ttl.jsonl"
	segment.FileID = segment.SourcePath + ":1:2:birth:100"
	segment.PreviousFileID = segment.FileID
	segment.AcceptedAt = time.Now().UTC().Add(-2 * time.Hour)
	segment.ArchiveMonth = segment.AcceptedAt.Format("200601")
	segment.RiskFeaturesRequired, segment.SplitRiskFeatures = true, true
	segment.Events[0].Source = "packet-sidecar"
	segment.Events[0].SourceEventType = "ttl"
	segment.Events[0].Type = "device"
	segment.Events[0].Timestamp = segment.AcceptedAt.Format(time.RFC3339Nano)
	segment.Events[0].Subject = map[string]any{"ip": "192.0.2.1"}
	second := segment.Events[0]
	second.EventID = "e2"
	segment.Events = append(segment.Events, second)
	for _, event := range segment.Events {
		line, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		segment.Raw = append(segment.Raw, append(line, '\n')...)
	}
	segment.RawIsStandardEvents = true
	segment.EndOffset = segment.StartOffset + int64(len(segment.Raw))
	sum := sha256.Sum256(segment.Raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil || len(features) != 2 {
		t.Fatalf("fixture feature count=%d err=%v", len(features), err)
	}
	return segment, prepared, features
}

func TestSettledPacketRiskRepairRequiresCompleteAbsenceAndQuietSinks(t *testing.T) {
	segment, prepared, features := settledPacketRiskFixture(t)
	id := streamlog.SourceSegmentID(segment)
	month, err := strconv.Atoi(segment.ArchiveMonth)
	if err != nil {
		t.Fatal(err)
	}
	mode := "partial"
	queueBusy, activeInsert := false, false
	inserts, queueChecks, activeChecks := 0, 0, 0
	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		switch q := string(query); {
		case strings.Contains(q, "FROM system.asynchronous_inserts"):
			queueChecks++
			if queueBusy {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(q, "FROM system.processes"):
			activeChecks++
			if activeInsert {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(q, "FROM stream_event_body_"):
			for _, item := range prepared {
				_ = json.NewEncoder(w).Encode(map[string]any{"scope_id": item.scope, "event_key": item.key, "content_sha256": item.hash})
			}
		case strings.Contains(q, "FROM stream_event_search"):
			for _, item := range prepared {
				_ = json.NewEncoder(w).Encode(map[string]any{"scope_id": item.scope, "protocol": "ttl", "observed_at": item.observed.Truncate(time.Microsecond).Format(time.RFC3339Nano),
					"event_key": item.key, "content_sha256": item.hash, "archive_month": month, "retention_class": item.retention})
			}
		case strings.Contains(q, "FROM stream_risk_features_v1"):
			if mode == "partial" || mode == "all" {
				count := 1
				if mode == "all" {
					count = len(features)
				}
				for _, feature := range features[:count] {
					_ = json.NewEncoder(w).Encode(map[string]any{"scope_id": feature.item.scope, "event_key": feature.item.key,
						"content_sha256": feature.item.hash, "feature_sha256": feature.featureHash,
						"feature_version": evidence.FeatureEventVersion, "archive_month": month})
				}
			}
		case strings.HasPrefix(q, "INSERT INTO stream_risk_features_v1"):
			inserts++
			token = r.URL.Query().Get("insert_deduplication_token")
			mode = "all"
		default:
			t.Errorf("unexpected settled risk feature query: %.80s", q)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ReconcileSettledStreamRiskFeatures(context.Background(), id, segment); !errors.Is(err, streamlog.ErrUnconfirmed) || inserts != 0 {
		t.Fatalf("partial feature insert was replayed: writes=%d err=%v", inserts, err)
	}
	mode, queueBusy = "missing", true
	if err := ch.ReconcileSettledStreamRiskFeatures(context.Background(), id, segment); !errors.Is(err, streamlog.ErrUnconfirmed) || inserts != 0 {
		t.Fatalf("busy async queue allowed repair: writes=%d err=%v", inserts, err)
	}
	queueBusy, activeInsert = false, true
	if err := ch.ReconcileSettledStreamRiskFeatures(context.Background(), id, segment); !errors.Is(err, streamlog.ErrUnconfirmed) || inserts != 0 {
		t.Fatalf("active INSERT allowed repair: writes=%d err=%v", inserts, err)
	}
	activeInsert = false
	if err := ch.ReconcileSettledStreamRiskFeatures(context.Background(), id, segment); err != nil || inserts != 1 || queueChecks < 2 || activeChecks < 2 {
		t.Fatalf("quiet all-missing features not repaired once: writes=%d queue=%d active=%d err=%v", inserts, queueChecks, activeChecks, err)
	}
	if token == "" || token == streamInsertSettings(id, "stream_risk_features_v1")["insert_deduplication_token"] {
		t.Fatal("settled repair did not use a distinct ClickHouse token")
	}
	if err := ch.ReconcileSettledStreamRiskFeatures(context.Background(), id, segment); err != nil || inserts != 1 {
		t.Fatalf("confirmed feature rows were duplicated: writes=%d err=%v", inserts, err)
	}
	segment.AcceptedAt = time.Now().UTC().Add(-30 * time.Minute)
	if err := ch.ReconcileSettledStreamRiskFeatures(context.Background(), streamlog.SourceSegmentID(segment), segment); !errors.Is(err, streamlog.ErrUnconfirmed) || inserts != 1 {
		t.Fatalf("recent segment used settled repair: writes=%d err=%v", inserts, err)
	}
}
