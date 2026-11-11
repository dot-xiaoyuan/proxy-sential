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
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestStreamBodiesBatchReadUsesBoundedPhysicalLocator(t *testing.T) {
	events := []normalized.Event{
		{EventID: "a", Timestamp: "2026-10-25T08:30:00Z", Type: "device"},
		{EventID: "b", Timestamp: "2026-10-25T08:30:01Z", Type: "device"},
	}
	refs := make([]StreamBodyRef, len(events))
	rows := make([]map[string]string, len(events))
	for i, event := range events {
		body, _ := json.Marshal(event)
		sum := sha256.Sum256(body)
		refs[i] = StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:" + event.EventID, SHA256: hex.EncodeToString(sum[:])}
		rows[i] = map[string]string{"scope_id": refs[i].Scope, "event_key": refs[i].Key, "content_sha256": refs[i].SHA256, "body": string(body)}
	}
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		queries = append(queries, string(query))
		for _, row := range rows {
			_ = json.NewEncoder(w).Encode(row)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ch.GetStreamEventsByRefs(context.Background(), refs)
	if err != nil || len(got) != 2 || got[refs[0]].EventID != "a" || got[refs[1]].EventID != "b" {
		t.Fatalf("batched evidence mismatch: got=%+v err=%v", got, err)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "archive_month=202610") || !strings.Contains(queries[0], "stream_event_body_evidence") || !strings.Contains(queries[0], "scope_id='scope-a' AND event_key IN") || !strings.Contains(queries[1], "scope_id='scope-a' AND (event_key,content_sha256) IN") || !strings.Contains(queries[1], "LIMIT 1 BY scope_id,event_key,content_sha256") {
		t.Fatalf("body read did not use narrow metadata and exact body queries: %+v", queries)
	}
	rows[1]["content_sha256"] = strings.Repeat("f", 64)
	if _, err := ch.GetStreamEventsByRefs(context.Background(), refs); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("same key with conflicting body was accepted: %v", err)
	}
}

func TestStreamBodiesBatchReadSeparatesScopesBeforeKeyLookup(t *testing.T) {
	refs := make([]StreamBodyRef, 0, 2)
	rows := map[string]map[string]string{}
	for _, scope := range []string{"scope-a", "scope-b"} {
		event := normalized.Event{EventID: scope, Timestamp: "2026-10-25T08:30:00Z", Type: "device"}
		body, _ := json.Marshal(event)
		sum := sha256.Sum256(body)
		ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: scope, Key: "shared-key", SHA256: hex.EncodeToString(sum[:])}
		refs = append(refs, ref)
		rows[scope] = map[string]string{"scope_id": scope, "event_key": ref.Key, "content_sha256": ref.SHA256, "body": string(body)}
	}
	queries := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		for scope, row := range rows {
			if strings.Contains(query, "scope_id='"+scope+"'") {
				queries[scope]++
				_ = json.NewEncoder(w).Encode(row)
				return
			}
		}
		t.Errorf("body lookup did not isolate scope: %s", query)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ch.GetStreamEventsByRefs(context.Background(), refs)
	if err != nil || len(got) != 2 || got[refs[0]].EventID != "scope-a" || got[refs[1]].EventID != "scope-b" || queries["scope-a"] != 2 || queries["scope-b"] != 2 {
		t.Fatalf("scoped body read: rows=%+v calls=%+v err=%v", got, queries, err)
	}
}

func TestStreamCoverageBodyCacheKeepsMetadataAndCaseVerification(t *testing.T) {
	event := normalized.Event{EventID: "coverage", Source: "handshake-sidecar", SourceEventType: "capture_coverage", Timestamp: "2026-10-25T08:30:00Z", Subject: map[string]any{"campus_id": "campus-a"}}
	body, _ := json.Marshal(event)
	sum := sha256.Sum256(body)
	ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:coverage", SHA256: hex.EncodeToString(sum[:])}
	var metadataReads, bodyReads int
	var conflict, corrupt bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		if strings.Contains(string(query), "SELECT scope_id,event_key,content_sha256,body FROM") {
			bodyReads++
			content := string(body)
			if corrupt {
				content += " "
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": ref.SHA256, "body": content})
			return
		}
		metadataReads++
		hash := ref.SHA256
		if conflict {
			hash = strings.Repeat("f", 64)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": hash})
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		got, err := ch.GetStreamEventsByRefs(context.Background(), []StreamBodyRef{ref})
		if err != nil || got[ref].EventID != event.EventID {
			t.Fatalf("coverage read %d: %+v %v", i, got, err)
		}
	}
	if metadataReads != 2 || bodyReads != 1 {
		t.Fatalf("cache skipped archive metadata or repeated the wide body read: metadata=%d body=%d", metadataReads, bodyReads)
	}
	conflict = true
	if _, err := ch.GetStreamEventsByRefs(context.Background(), []StreamBodyRef{ref}); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("late conflicting archive row passed cache: %v", err)
	}
	conflict, corrupt = false, true
	if _, err := ch.getStreamBodiesByRefs(context.Background(), []StreamBodyRef{ref}, false); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("case path accepted changed authoritative bytes: %v", err)
	}
	if metadataReads != 4 || bodyReads != 2 {
		t.Fatalf("case path reused live cache: metadata=%d body=%d", metadataReads, bodyReads)
	}
}
