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

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestStreamBodyRefReadsOnlyItsPartitionAndVerifiesHash(t *testing.T) {
	event := normalized.Event{EventID: "event-1", SchemaVersion: "v1", Type: "discovery", Timestamp: "2026-10-24T10:00:00Z"}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-1", SHA256: hex.EncodeToString(hash[:])}
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		query = string(data)
		row, _ := json.Marshal(map[string]string{"content_sha256": ref.SHA256, "body": string(body)})
		_, _ = w.Write(append(row, '\n'))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := ch.GetStreamEventByRef(context.Background(), ref)
	if err != nil || !found || got.EventID != event.EventID {
		t.Fatalf("body lookup: %+v %t %v", got, found, err)
	}
	for _, fragment := range []string{"stream_event_body_evidence", "archive_month=202610", "scope_id='scope-a'", "event_key='fresh:event-1'"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("lookup lacks %s: %s", fragment, query)
		}
	}
}

func TestStreamBodyRefRejectsInvalidOrChangedBody(t *testing.T) {
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ch.GetStreamEventByRef(context.Background(), StreamBodyRef{Class: "other", Month: "202610", Scope: "x", Key: "k", SHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("accepted invalid table class")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"content_sha256":"`+strings.Repeat("0", 64)+`","body":"{}"}`+"\n")
	}))
	defer server.Close()
	ch, err = NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ch.GetStreamEventByRef(context.Background(), StreamBodyRef{Class: "short", Month: "202610", Scope: "scope", Key: "key", SHA256: strings.Repeat("0", 64)})
	if !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("changed body was accepted: %v", err)
	}
}

func TestStreamBodyRefRejectsConflictingVersionAtSameKey(t *testing.T) {
	event := normalized.Event{EventID: "event-1", SchemaVersion: "v1", Type: "discovery", Timestamp: "2026-10-24T10:00:00Z"}
	body, _ := json.Marshal(event)
	sum := sha256.Sum256(body)
	ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-1", SHA256: hex.EncodeToString(sum[:])}
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		query = string(data)
		good, _ := json.Marshal(map[string]string{"content_sha256": ref.SHA256, "body": string(body)})
		bad, _ := json.Marshal(map[string]string{"content_sha256": strings.Repeat("0", 64), "body": "{}"})
		_, _ = w.Write(append(good, '\n'))
		_, _ = w.Write(append(bad, '\n'))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ch.GetStreamEventByRef(context.Background(), ref); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("same-key conflicting version was accepted: %v", err)
	}
	if strings.Contains(query, "content_sha256=") {
		t.Fatalf("conflicting version would be hidden by hash filter: %s", query)
	}
}

func TestStreamEvidenceRefReadsAndVerifiesOriginalSourceBytes(t *testing.T) {
	event := normalized.Event{EventID: "event-1", SchemaVersion: "v1", Type: "discovery", Timestamp: "2026-10-24T10:00:00Z"}
	body, _ := json.Marshal(event)
	bodySum := sha256.Sum256(body)
	raw := []byte("#path dhcp\noriginal\n")
	rawSum := sha256.Sum256(raw)
	ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-1", SHA256: hex.EncodeToString(bodySum[:])}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		row := map[string]string{}
		if strings.Contains(string(query), "stream_source_raw") {
			row["raw_sha256"] = hex.EncodeToString(rawSum[:])
			row["raw_base64"] = base64.StdEncoding.EncodeToString(raw)
		} else {
			row["content_sha256"] = ref.SHA256
			row["body"] = string(body)
			row["raw_segment_id"] = "segment-1"
			row["raw_sha256"] = hex.EncodeToString(rawSum[:])
		}
		encoded, _ := json.Marshal(row)
		_, _ = w.Write(append(encoded, '\n'))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	evidence, found, err := ch.GetStreamEvidenceByRef(context.Background(), ref)
	if err != nil || !found || evidence.Event.EventID != event.EventID || string(evidence.RawSource) != string(raw) {
		t.Fatalf("verified evidence: %+v %t %v", evidence, found, err)
	}
}
