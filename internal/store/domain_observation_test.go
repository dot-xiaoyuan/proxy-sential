package store

import (
	"context"
	"testing"

	"proxy-sentinel/internal/normalized"
)

type domainAttributionResolver struct {
	item  IdentityAttribution
	found bool
}

func (r domainAttributionResolver) ResolveIdentityAt(context.Context, string, string) (IdentityAttribution, bool, error) {
	return r.item, r.found, nil
}

func TestExtractDomainObservationStandardEvents(t *testing.T) {
	tests := []struct{ eventType, field, value, expected string }{
		{"dns", "query", "Push.Apple.COM.", "push.apple.com"},
		{"tls", "sni", "api.huawei.com", "api.huawei.com"},
		{"quic", "sni", "服务.小米.com", "xn--zfr188b.xn--yets76e.com"},
		{"http", "host", "updates.windows.com:443", "updates.windows.com"},
	}
	for _, item := range tests {
		event := normalized.Event{EventID: item.eventType + "-1", Type: item.eventType, Timestamp: "2026-09-02T10:00:00Z", Subject: map[string]any{"ip": "192.0.2.10", "endpoint_id": "endpoint-explicit"}, Flow: map[string]any{}, Payload: map[string]any{item.field: item.value}}
		observation, ok := ExtractDomainObservation(event)
		if !ok || observation.Domain != item.expected || observation.EventSource != item.eventType || observation.AttributionMethod != "explicit_endpoint" {
			t.Fatalf("%s observation mismatch: %+v ok=%v", item.eventType, observation, ok)
		}
	}
}

func TestDomainObservationAttributionAndUnattributedScenarios(t *testing.T) {
	event := normalized.Event{EventID: "tls-session", Type: "tls", Timestamp: "2026-09-02T10:00:00Z", Subject: map[string]any{"ip": "192.0.2.20"}, Flow: map[string]any{}, Payload: map[string]any{"sni": "device.example.test"}}
	observation, ok := ExtractDomainObservation(event)
	if !ok {
		t.Fatal("expected observable SNI")
	}
	attributed, ok, err := AttributeDomainObservation(context.Background(), observation, domainAttributionResolver{item: IdentityAttribution{SessionID: "session-1", EndpointID: "endpoint-session"}, found: true})
	if err != nil || !ok || attributed.EndpointID != "endpoint-session" || attributed.AttributionMethod != "active_auth_session" {
		t.Fatalf("active session attribution failed: %+v ok=%v err=%v", attributed, ok, err)
	}
	for name, resolver := range map[string]domainAttributionResolver{
		"missing":  {},
		"conflict": {found: true, item: IdentityAttribution{EndpointID: "endpoint-a", Conflict: true}},
	} {
		if result, found, err := AttributeDomainObservation(context.Background(), observation, resolver); err != nil || found || result.EndpointID != "" {
			t.Fatalf("%s should remain unattributed: %+v found=%v err=%v", name, result, found, err)
		}
	}
	for _, hidden := range []normalized.Event{
		{Type: "tls", Payload: map[string]any{}},
		{Type: "dns", Payload: map[string]any{}},
		{Type: "flow", Payload: map[string]any{"host": "apple.com"}},
	} {
		if _, ok := ExtractDomainObservation(hidden); ok {
			t.Fatalf("event without observable standard domain must be ignored: %+v", hidden)
		}
	}
}

func TestNormalizeDomainRejectsLookalikesAndNonDomains(t *testing.T) {
	for _, value := range []string{"https://apple.com/path", "192.0.2.1", "bad..apple.com", "-bad.apple.com"} {
		if domain, err := NormalizeDomain(value); err == nil || domain != "" {
			t.Fatalf("expected %q rejection, got domain=%q err=%v", value, domain, err)
		}
	}
}
