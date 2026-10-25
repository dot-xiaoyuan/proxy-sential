package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

type streamEventAPIReader struct {
	store.Reader
	query store.StreamEventIndexQuery
	ref   store.StreamBodyRef
}

func (r *streamEventAPIReader) ListStreamEventIndex(_ context.Context, query store.StreamEventIndexQuery) (store.StreamEventIndexPage, error) {
	r.query = query
	return store.StreamEventIndexPage{Items: []store.StreamEventIndexItem{{EventKey: "fresh:event-a"}}}, nil
}

func (r *streamEventAPIReader) GetStreamEventByRef(_ context.Context, ref store.StreamBodyRef) (normalized.Event, bool, error) {
	r.ref = ref
	return normalized.Event{EventID: "event-a"}, true, nil
}

func TestStreamEventAPIRequiresBoundedInputsAndExactRef(t *testing.T) {
	reader := &streamEventAPIReader{}
	server := &Server{reader: reader}
	bad := httptest.NewRecorder()
	server.handleStreamEventIndex(bad, httptest.NewRequest(http.MethodGet, "/events/stream-index?scope_id=scope-a", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("unbounded query status=%d", bad.Code)
	}
	good := httptest.NewRecorder()
	server.handleStreamEventIndex(good, httptest.NewRequest(http.MethodGet,
		"/events/stream-index?scope_id=scope-a&protocol=ssdp&from=2026-10-25T20:00:00Z&to=2026-10-25T20:15:00Z&limit=20", nil))
	if good.Code != http.StatusOK || reader.query.ScopeID != "scope-a" || reader.query.Protocol != "ssdp" || reader.query.Limit != 20 ||
		reader.query.To.Sub(reader.query.From) != 15*time.Minute {
		t.Fatalf("bounded query status=%d query=%+v", good.Code, reader.query)
	}
	ref := store.StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-a", SHA256: strings.Repeat("a", 64)}
	encoded, _ := json.Marshal(ref)
	detail := httptest.NewRecorder()
	server.handleStreamEventBody(detail, httptest.NewRequest(http.MethodGet, "/events/stream-body?ref="+url.QueryEscape(string(encoded)), nil))
	if detail.Code != http.StatusOK || reader.ref != ref || !strings.Contains(detail.Body.String(), `"event_id":"event-a"`) {
		t.Fatalf("detail status=%d ref=%+v body=%s", detail.Code, reader.ref, detail.Body.String())
	}
}
