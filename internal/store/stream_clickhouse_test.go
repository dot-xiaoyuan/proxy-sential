package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestStreamWriteUsesPreparedBatchWithoutNormalPathLookup(t *testing.T) {
	var queries []string
	var tokens []string
	var asyncSettings []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		queries = append(queries, string(body))
		tokens = append(tokens, r.URL.Query().Get("insert_deduplication_token"))
		asyncSettings = append(asyncSettings, r.URL.Query().Get("async_insert")+"/"+r.URL.Query().Get("wait_for_async_insert")+"/"+r.URL.Query().Get("async_insert_deduplicate"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	segment := streamlog.Segment{Epoch: "cutover-1", Source: "zeek-dhcp", SourcePath: "/logs/dhcp.log", FileID: "file-1", StartOffset: 0, EndOffset: 100, ParserVersion: "v1", ArchiveMonth: "202610", AcceptedAt: time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC), NeedsProjection: true,
		Events: []normalized.Event{{EventID: "e1", SchemaVersion: "v1", Source: "zeek", SourceEventType: "dhcp", Type: "discovery", Timestamp: "2026-10-24T10:00:00Z", Observer: map[string]any{"sensor_id": "sensor", "capture_scope_id": "scope"}, Subject: map[string]any{"ip": "192.0.2.1", "mac": "00:11:22:33:44:55"}, Payload: map[string]any{"origin": "dhcp"}}}}
	if err := ch.WriteStreamBody(context.Background(), "segment-one", segment); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteStreamSearch(context.Background(), "segment-one", segment); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 {
		t.Fatalf("expected body and narrow search inserts: %d", len(queries))
	}
	for i, query := range queries {
		if !strings.HasPrefix(query, "INSERT INTO stream_event_") || strings.Contains(strings.ToUpper(query), "SELECT") {
			t.Fatalf("unexpected query %d: %s", i, query)
		}
		if tokens[i] == "" {
			t.Fatalf("missing fixed dedup token for query %d", i)
		}
		if asyncSettings[i] != "1/1/1" {
			t.Fatalf("unsafe async acknowledgement for query %d: %s", i, asyncSettings[i])
		}
	}
	if !strings.Contains(queries[0], "stream_event_body_evidence") || !strings.Contains(queries[1], "stream_event_search") {
		t.Fatalf("wrong write order: %v", queries)
	}
	if strings.Contains(queries[1], "payload_json") || strings.Contains(queries[1], "origin") {
		t.Fatalf("search contains full payload: %s", queries[1])
	}
}

func TestOperationalCoverageEventUsesShortBodyRetention(t *testing.T) {
	segment := streamlog.Segment{Epoch: "fresh", ArchiveMonth: "202610", AcceptedAt: time.Date(2026, 10, 25, 4, 0, 0, 0, time.UTC), Events: []normalized.Event{{EventID: "coverage-1", Type: "device", SourceEventType: "capture_coverage", Timestamp: "2026-10-25T04:00:00Z", Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a"}, Subject: map[string]any{"campus_id": "campus-a"}, Payload: map[string]any{"capture_coverage": true}}}}
	prepared, err := prepareStreamEvents(segment)
	if err != nil || len(prepared) != 1 || prepared[0].retention != "short" {
		t.Fatalf("coverage diagnostic was retained as one-year evidence: %+v %v", prepared, err)
	}
}

func TestMixedSignalSegmentRetainsOnlySelectedDiscoveryEvent(t *testing.T) {
	segment := streamlog.Segment{Epoch: "fresh", ArchiveMonth: "202610", AcceptedAt: time.Date(2026, 10, 25, 4, 0, 0, 0, time.UTC), NeedsProjection: true,
		Events: []normalized.Event{
			{EventID: "ssdp-1", Source: "packet-sidecar", Type: "device", SourceEventType: "ssdp", Timestamp: "2026-10-25T04:00:00Z", Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a"}, Subject: map[string]any{"ip": "192.0.2.10"}},
			{EventID: "ttl-1", Source: "packet-sidecar", Type: "device", SourceEventType: "ttl", Timestamp: "2026-10-25T04:00:01Z", Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a"}, Subject: map[string]any{"ip": "192.0.2.11"}},
		}}
	prepared, err := prepareStreamEvents(segment)
	if err != nil || len(prepared) != 2 || prepared[0].retention != "evidence" || prepared[1].retention != "short" {
		t.Fatalf("mixed segment retained unrelated signal as one-year evidence: %+v %v", prepared, err)
	}
}

func TestStreamSignalRetentionFollowsActualReader(t *testing.T) {
	for _, tc := range []struct {
		source, kind, want string
	}{
		{"packet-sidecar", "ieee1905_topology", "short"},
		{"packet-sidecar", "ieee1905_client_association", "evidence"},
		{"packet-sidecar", "ieee1905_client_snapshot", "evidence"},
		{"handshake-sidecar", "handshake", "evidence"},
		{"packet-sidecar", "ttl", "short"},
	} {
		event := normalized.Event{Type: "device", Source: tc.source, SourceEventType: tc.kind}
		if got := streamEventRetention(event); got != tc.want {
			t.Fatalf("%s/%s retention=%s want %s", tc.source, tc.kind, got, tc.want)
		}
	}
}

func TestSharedCoverageKeepsAuthorityUntilDecisionArchive(t *testing.T) {
	for _, source := range []string{"handshake-sidecar", "packet-sidecar"} {
		segment := streamlog.Segment{Epoch: "fresh", ArchiveMonth: "202610", AcceptedAt: time.Date(2026, 10, 25, 4, 0, 0, 0, time.UTC), Events: []normalized.Event{{EventID: "coverage-1", Source: source, Type: "device", SourceEventType: "capture_coverage", Timestamp: "2026-10-25T04:00:00Z", Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a"}, Subject: map[string]any{"campus_id": "campus-a"}, Payload: map[string]any{"access_domain": "bond0", "capture_coverage": true}}}}
		prepared, err := prepareStreamEvents(segment)
		if err != nil || len(prepared) != 1 || prepared[0].retention != "evidence" {
			t.Fatalf("%s coverage needed by shared decisions was dropped early: %+v %v", source, prepared, err)
		}
	}
}

func TestSharedStreamSearchCarriesOnlyNarrowScopeFields(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query = string(body)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	segment := streamlog.Segment{Epoch: "fresh", Source: "device-signals", SourcePath: "/signals/handshake.jsonl", FileID: "file-one", StartOffset: 0, EndOffset: 100,
		ParserVersion: "device-signals-v1", ArchiveMonth: "202610", AcceptedAt: time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC),
		Events: []normalized.Event{{EventID: "handshake-one", Source: "handshake-sidecar", SourceEventType: "handshake", Type: "device", Timestamp: "2026-10-25T10:00:00Z",
			Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a", "collector_instance_id": "collector-a"},
			Subject:  map[string]any{"campus_id": "site-a", "ip": "10.2.3.4"}, Payload: map[string]any{"access_domain": "bond0", "sni": "private.example", "secret_test_marker": "body-only"}}}}
	if err := ch.WriteStreamSearch(context.Background(), "segment-one", segment); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, `"campus_id":"site-a"`) || !strings.Contains(query, `"access_domain":"bond0"`) || !strings.Contains(query, `"collector_instance_id":"collector-a"`) || strings.Contains(query, "secret_test_marker") || strings.Contains(query, "body-only") {
		t.Fatalf("shared stream lookup lost scope or copied body: %s", query)
	}
}

func TestPositionKeysKeepRepeatedIdentityRecordsAndPartialRepairStable(t *testing.T) {
	segment := testStreamSegment()
	segment.KeyScheme = "source_position_v1"
	segment.Source = "identity-http"
	segment.ParserVersion = "identity-http-v2"
	segment.StartOffset = 50
	segment.EndOffset = 52
	segment.Events = []normalized.Event{segment.Events[0], segment.Events[0]}
	first, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].key == first[1].key || first[0].hash != first[1].hash {
		t.Fatalf("repeated input positions collapsed: %+v", first)
	}
	partial := segment
	partial.Events = segment.Events[1:]
	partial.EventOffsets = []int64{51}
	repaired, err := prepareStreamEvents(partial)
	if err != nil {
		t.Fatal(err)
	}
	if repaired[0].key != first[1].key {
		t.Fatalf("partial repair changed fixed position key: %q != %q", repaired[0].key, first[1].key)
	}
}

func TestStreamWriteRetainsRawSourceOncePerSegment(t *testing.T) {
	segment := testStreamSegment()
	segment.Raw = []byte("#path dhcp\nrecord\n")
	sum := sha256.Sum256(segment.Raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		queries = append(queries, string(data))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteStreamBody(context.Background(), "segment-one", segment); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !strings.HasPrefix(queries[0], "INSERT INTO stream_source_raw") || strings.Count(queries[0], `"raw_base64"`) != 1 {
		t.Fatalf("raw source was not retained once: %v", queries)
	}
	if !strings.Contains(queries[1], `"raw_segment_id":"segment-one"`) {
		t.Fatalf("standard event lost raw locator: %s", queries[1])
	}
}

func TestStandardEventSourceDoesNotArchiveDuplicateRawLines(t *testing.T) {
	segment := testStreamSegment()
	segment.Source = "device-signals"
	segment.Raw = []byte(`{"schema_version":"v1","type":"device"}` + "\n")
	segment.RawIsStandardEvents = true
	sum := sha256.Sum256(segment.Raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		queries = append(queries, string(body))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteStreamBody(context.Background(), "segment-one", segment); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 1 || !strings.HasPrefix(queries[0], "INSERT INTO stream_event_body_") || strings.Contains(queries[0], "raw_segment_id\":\"segment-one") {
		t.Fatalf("standard-event source created a duplicate raw archive: %v", queries)
	}
}

func TestReconcileStreamBodyRestoresMissingRawWithoutResendingPresentEvent(t *testing.T) {
	segment := testStreamSegment()
	segment.Raw = []byte("source-record\n")
	sum := sha256.Sum256(segment.Raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	var rawInserted bool
	var eventInserts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		switch {
		case strings.HasPrefix(query, "SELECT raw_sha256"):
			if rawInserted {
				row, _ := json.Marshal(map[string]string{"raw_sha256": segment.RawSHA256, "raw_base64": base64.StdEncoding.EncodeToString(segment.Raw)})
				_, _ = w.Write(append(row, '\n'))
			}
		case strings.HasPrefix(query, "INSERT INTO stream_source_raw"):
			rawInserted = true
		case strings.HasPrefix(query, "SELECT scope_id"):
			row, _ := json.Marshal(map[string]string{"scope_id": prepared[0].scope, "event_key": prepared[0].key, "content_sha256": prepared[0].hash})
			_, _ = w.Write(append(row, '\n'))
		case strings.HasPrefix(query, "INSERT INTO stream_event_body_"):
			eventInserts++
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ReconcileStreamBody(context.Background(), "segment-one", segment); err != nil {
		t.Fatal(err)
	}
	if !rawInserted || eventInserts != 0 {
		t.Fatalf("unexpected recovery writes: raw=%t events=%d", rawInserted, eventInserts)
	}
}

func TestVerifyStreamBodyDistinguishesMissingFromConflictingContent(t *testing.T) {
	segment := streamlog.Segment{Epoch: "cutover-1", Source: "zeek-dhcp", SourcePath: "/logs/dhcp.log", FileID: "file-1", StartOffset: 0, EndOffset: 100, ParserVersion: "v1", ArchiveMonth: "202610", AcceptedAt: time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC), NeedsProjection: true,
		Events: []normalized.Event{{EventID: "e1", Timestamp: "2026-10-24T10:00:00Z", Observer: map[string]any{"capture_scope_id": "scope"}}}}
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	response := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, response) }))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if found, err := ch.VerifyStreamBody(context.Background(), segment); err != nil || found {
		t.Fatalf("missing body: found=%t err=%v", found, err)
	}
	response = `{"scope_id":"scope","event_key":"cutover-1:e1","content_sha256":"` + prepared[0].hash + `"}` + "\n"
	if found, err := ch.VerifyStreamBody(context.Background(), segment); err != nil || !found {
		t.Fatalf("committed body: found=%t err=%v", found, err)
	}
	response = `{"scope_id":"scope","event_key":"cutover-1:e1","content_sha256":"other"}` + "\n"
	if found, err := ch.VerifyStreamBody(context.Background(), segment); !errors.Is(err, streamlog.ErrContentConflict) || found {
		t.Fatalf("content conflict: found=%t err=%v", found, err)
	}
}

func TestReconcileStreamBodyWritesOnlyConfirmedMissingRows(t *testing.T) {
	segment := streamlog.Segment{Epoch: "cutover-1", Source: "zeek-dhcp", SourcePath: "/logs/dhcp.log", FileID: "file-1", StartOffset: 0, EndOffset: 200, ParserVersion: "v1", ArchiveMonth: "202610", AcceptedAt: time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC), NeedsProjection: true,
		Events: []normalized.Event{
			{EventID: "e1", Timestamp: "2026-10-24T10:00:00Z", Observer: map[string]any{"capture_scope_id": "scope"}},
			{EventID: "e2", Timestamp: "2026-10-24T10:00:01Z", Observer: map[string]any{"capture_scope_id": "scope"}},
		}}
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	committed := map[string]string{prepared[0].key: prepared[0].hash}
	insertRows := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(string(body), "SELECT") {
			for key, hash := range committed {
				row, _ := json.Marshal(map[string]string{"scope_id": "scope", "event_key": key, "content_sha256": hash})
				_, _ = w.Write(append(row, '\n'))
			}
			return
		}
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n")[1:] {
			var row struct {
				Key  string `json:"event_key"`
				Hash string `json:"content_sha256"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Errorf("bad insert row: %v", err)
				continue
			}
			committed[row.Key] = row.Hash
			insertRows++
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ReconcileStreamBody(context.Background(), "segment-one", segment); err != nil {
		t.Fatal(err)
	}
	if insertRows != 1 || committed[prepared[1].key] != prepared[1].hash {
		t.Fatalf("incorrect partial recovery: rows=%d committed=%v", insertRows, committed)
	}
}

func TestStreamReconciliationAcceptsIdenticalDuplicateRowsButRejectsConflict(t *testing.T) {
	segment := testStreamSegment()
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"scope_id": prepared[0].scope, "event_key": prepared[0].key,
		"content_sha256": prepared[0].hash, "archive_month": uint32(202610), "retention_class": "evidence"}
	conflicting := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.HasPrefix(string(body), "SELECT") {
			t.Errorf("reconciliation unexpectedly wrote %s", string(body))
			return
		}
		for range 2 {
			item := map[string]any{}
			for key, value := range row {
				item[key] = value
			}
			if conflicting {
				item["content_sha256"] = "other"
			}
			encoded, _ := json.Marshal(item)
			_, _ = w.Write(append(encoded, '\n'))
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if found, err := ch.VerifyStreamSearch(context.Background(), segment); err != nil || !found {
		t.Fatalf("identical duplicate search row was treated as conflict: found=%t err=%v", found, err)
	}
	if found, err := ch.VerifyStreamBody(context.Background(), segment); err != nil || !found {
		t.Fatalf("identical duplicate body row was treated as conflict: found=%t err=%v", found, err)
	}
	conflicting = true
	if found, err := ch.VerifyStreamSearch(context.Background(), segment); !errors.Is(err, streamlog.ErrContentConflict) || found {
		t.Fatalf("different search content was accepted: found=%t err=%v", found, err)
	}
}
