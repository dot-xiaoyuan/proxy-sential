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

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func settledPassiveSegment() (string, streamlog.Segment) {
	accepted := time.Now().UTC().Add(-2 * time.Hour)
	s := streamlog.Segment{
		Epoch: "passive-fresh", Source: "passive-discovery", SourcePath: "packet://bond0/passive-sensor",
		FileID: "collector-1", PreviousFileID: "collector-1", PreviousOffset: 100,
		StartOffset: 100, EndOffset: 200, ParserVersion: "passive-frame-v1",
		ArchiveMonth: accepted.Format("200601"), AcceptedAt: accepted, NeedsProjection: true,
	}
	id := streamlog.SourceSegmentID(s)
	for i := 0; i < 2; i++ {
		s.Events = append(s.Events, normalized.Event{
			EventID:   "stream3-" + id + "-" + string(rune('0'+i)),
			Timestamp: accepted.Format(time.RFC3339Nano), Source: "passive", SourceEventType: "arp", Type: "discovery",
			Observer: map[string]any{"capture_scope_id": "scope", "sensor_id": "sensor"},
			Subject:  map[string]any{"ip": "192.0.2.1"},
			RawRef:   map[string]any{"backend": "passive-discovery", "producer_event_id": "producer", "source_offset": float64(s.StartOffset), "source_record_ordinal": float64(i), "raw_packet_available": false},
		})
	}
	return id, s
}

func TestSettledPassiveArchiveRequiresJournalIdentityAndQuietBody(t *testing.T) {
	id, segment := settledPassiveSegment()
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	busy, inserted, writes := true, false, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		switch {
		case strings.Contains(query, "FROM system.asynchronous_inserts"):
			if busy {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(query, "FROM system.processes"):
			_, _ = io.WriteString(w, "0\n")
		case strings.HasPrefix(query, "SELECT scope_id,event_key,content_sha256"):
			_ = json.NewEncoder(w).Encode(map[string]string{"scope_id": prepared[0].scope, "event_key": prepared[0].key, "content_sha256": prepared[0].hash})
			if inserted {
				_ = json.NewEncoder(w).Encode(map[string]string{"scope_id": prepared[1].scope, "event_key": prepared[1].key, "content_sha256": prepared[1].hash})
			}
		case strings.HasPrefix(query, "INSERT INTO stream_event_body_"):
			if !strings.Contains(query, `"event_key":"`+prepared[1].key+`"`) || strings.Contains(query, `"event_key":"`+prepared[0].key+`"`) {
				t.Errorf("repair did not isolate the missing key")
			}
			writes++
			inserted = true
		case strings.Contains(query, "system.query_log") || strings.Contains(query, "stream_source_raw"):
			t.Errorf("passive body repair touched unrelated table")
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ReconcileSettledStreamBody(context.Background(), id, segment); err == nil || writes != 0 {
		t.Fatalf("busy insert queue was ignored: writes=%d err=%v", writes, err)
	}
	busy = false
	bad := segment
	bad.Events = append([]normalized.Event(nil), segment.Events...)
	bad.Events[0].EventID = "wrong-event-id"
	if err := ch.ReconcileSettledStreamBody(context.Background(), id, bad); !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("bad event identity accepted: %v", err)
	}
	bad = segment
	bad.Events = append([]normalized.Event(nil), segment.Events...)
	bad.Events[0].RawRef = map[string]any{"backend": "passive-discovery", "producer_event_id": "producer", "source_offset": float64(101), "source_record_ordinal": float64(0), "raw_packet_available": false}
	if err := ch.ReconcileSettledStreamBody(context.Background(), id, bad); !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("bad source offset accepted: %v", err)
	}
	if err := ch.ReconcileSettledStreamBody(context.Background(), id, segment); err != nil || writes != 1 {
		t.Fatalf("settled passive repair failed: writes=%d err=%v", writes, err)
	}
	if err := ch.ReconcileSettledStreamBody(context.Background(), id, segment); err != nil || writes != 1 {
		t.Fatalf("confirmed passive body duplicated: writes=%d err=%v", writes, err)
	}
}

func TestSettledBirthAwareSearchConfirmsPresentRowsWithoutReinsertion(t *testing.T) {
	segment := testStreamSegment()
	segment.Source = "device-signals"
	segment.SourcePath = "/signals/ttl.jsonl"
	segment.FileID = "/signals/ttl.jsonl:1:2:birth:100"
	segment.PreviousFileID = segment.FileID
	segment.Events[0].Source = "packet-sidecar"
	segment.Events[0].SourceEventType = "ttl"
	segment.AcceptedAt = time.Now().UTC().Add(-2 * time.Hour)
	segment.ArchiveMonth = segment.AcceptedAt.Format("200601")
	segment.Events[0].Timestamp = segment.AcceptedAt.Format(time.RFC3339Nano)
	second := segment.Events[0]
	second.EventID = "e2"
	segment.Events = append(segment.Events, second)
	firstLine, _ := json.Marshal(segment.Events[0])
	secondLine, _ := json.Marshal(segment.Events[1])
	segment.Raw = append(append(append([]byte{}, firstLine...), '\n'), append(secondLine, '\n')...)
	segment.RawIsStandardEvents = true
	segment.EndOffset = segment.StartOffset + int64(len(segment.Raw))
	sum := sha256.Sum256(segment.Raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	month, _ := strconv.ParseUint(segment.ArchiveMonth, 10, 32)
	searchReads, inserts := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		switch {
		case strings.HasPrefix(query, "SELECT scope_id,event_key,content_sha256 FROM stream_event_body_"):
			for _, item := range prepared {
				_ = json.NewEncoder(w).Encode(map[string]string{"scope_id": item.scope, "event_key": item.key, "content_sha256": item.hash})
			}
		case strings.HasPrefix(query, "SELECT scope_id,protocol,observed_at,event_key,content_sha256"):
			searchReads++
			if !strings.Contains(query, "PREWHERE scope_id='scope' AND protocol='ttl'") || strings.Count(query, "'fresh:e") > 100 {
				t.Errorf("search verification did not use bounded primary-key scope")
			}
			for _, item := range prepared {
				_ = json.NewEncoder(w).Encode(map[string]any{"scope_id": item.scope, "protocol": "ttl", "observed_at": item.observed.Format("2006-01-02 15:04:05.000000"), "event_key": item.key, "content_sha256": item.hash, "archive_month": month, "retention_class": item.retention, "body_ref": ""})
			}
		case strings.Contains(query, "FROM system.asynchronous_inserts") || strings.Contains(query, "FROM system.processes"):
			_, _ = io.WriteString(w, "1\n") // A confirmed read needs no write-side quiet interval.
		case strings.HasPrefix(query, "INSERT INTO") || strings.Contains(query, "FROM system.query_log"):
			inserts++
			t.Errorf("confirmed search was written or diagnostic log was read")
		default:
			t.Errorf("unexpected search proof query: %.120s", query)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ReconcileSettledStreamSearch(context.Background(), "segment", segment); err != nil || searchReads == 0 || inserts != 0 {
		t.Fatalf("settled search did not confirm present rows: reads=%d inserts=%d err=%v", searchReads, inserts, err)
	}
	segment.RiskFeaturesRequired = true
	if err := ch.ReconcileSettledStreamSearch(context.Background(), "segment", segment); !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("coupled risk features were accepted: %v", err)
	}
}
