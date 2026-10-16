package routerprober

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestTryPort_ServerAndTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "MikroTik/RouterOS/7.1")
		w.WriteHeader(200)
		w.Write([]byte(`<html><head><title>RouterOS</title></head></html>`))
	}))
	defer srv.Close()

	// Extract host and port from the test server URL
	addr := strings.TrimPrefix(srv.URL, "http://")
	host := addr[:strings.LastIndex(addr, ":")]
	portStr := addr[strings.LastIndex(addr, ":")+1:]
	var port int
	if _, err := (&http.Client{}).Head(srv.URL); err != nil {
		t.Fatal(err)
	}
	_ = portStr
	_ = host

	r := tryPort(t.Context(), host, func() int {
		var p int
		for _, c := range portStr {
			p = p*10 + int(c-'0')
		}
		return p
	}(), false)
	if r == nil {
		t.Fatal("expected probe result, got nil")
	}
	if r.server != "MikroTik/RouterOS/7.1" {
		t.Errorf("server = %q, want MikroTik/RouterOS/7.1", r.server)
	}
	if r.title != "RouterOS" {
		t.Errorf("title = %q, want RouterOS", r.title)
	}
	_ = port
}

func TestBuildEvent_Fields(t *testing.T) {
	target := routerTarget{
		assessmentID: "aaa-111",
		ip:           "192.168.1.1",
		mac:          "aa:bb:cc:dd:ee:ff",
	}
	servers := map[string]bool{"MikroTik/RouterOS/7.1": true}
	titles := map[string]bool{"RouterOS": true}
	locations := map[string]bool{}

	event := buildEvent(target, "sensor-test", servers, titles, locations)

	if event.SourceEventType != "http" {
		t.Errorf("SourceEventType = %q, want http", event.SourceEventType)
	}
	if event.Source != "router-prober" {
		t.Errorf("Source = %q, want router-prober", event.Source)
	}
	if !strings.HasPrefix(event.EventID, "rprobe-") {
		t.Errorf("EventID = %q, want rprobe- prefix", event.EventID)
	}

	// EventID is stable for same inputs
	event2 := buildEvent(target, "sensor-test", servers, titles, locations)
	if event.EventID != event2.EventID {
		t.Errorf("EventID not stable: %q vs %q", event.EventID, event2.EventID)
	}

	// Check payload fields
	payload := event.Payload
	if payload["server"] != "MikroTik/RouterOS/7.1" {
		t.Errorf("payload.server = %v", payload["server"])
	}
	if payload["title"] != "RouterOS" {
		t.Errorf("payload.title = %v", payload["title"])
	}
	if payload["assessment_id"] != "aaa-111" {
		t.Errorf("payload.assessment_id = %v", payload["assessment_id"])
	}
}

func TestBuildEvent_EmitsValidNormalizedEvent(t *testing.T) {
	target := routerTarget{assessmentID: "bbb-222", ip: "10.0.0.1"}
	servers := map[string]bool{"lighttpd/1.4": true}
	event := buildEvent(target, "sensor-x", servers, nil, nil)

	// Must round-trip through JSON as a normalized.Event
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var decoded normalized.Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != "v1" {
		t.Errorf("SchemaVersion = %q", decoded.SchemaVersion)
	}
}

func TestTryPort_Unreachable(t *testing.T) {
	// Port on localhost that is almost certainly not listening
	r := tryPort(t.Context(), "127.0.0.1", 19191, false)
	if r != nil {
		t.Errorf("expected nil for unreachable port, got %+v", r)
	}
}
