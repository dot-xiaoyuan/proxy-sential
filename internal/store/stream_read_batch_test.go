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
	if len(queries) != 2 || !strings.Contains(queries[0], "archive_month=202610") || !strings.Contains(queries[0], "stream_event_body_evidence") || !strings.Contains(queries[0], "(scope_id,event_key) IN") || !strings.Contains(queries[1], "(scope_id,event_key,content_sha256) IN") || !strings.Contains(queries[1], "LIMIT 1 BY scope_id,event_key,content_sha256") {
		t.Fatalf("body read did not use narrow metadata and exact body queries: %+v", queries)
	}
	rows[1]["content_sha256"] = strings.Repeat("f", 64)
	if _, err := ch.GetStreamEventsByRefs(context.Background(), refs); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("same key with conflicting body was accepted: %v", err)
	}
}
