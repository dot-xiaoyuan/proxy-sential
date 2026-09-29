package controlplane

import (
	"net/url"
	"testing"
)

func TestRouterObservationQueryAllFilters(t *testing.T) {
	values := url.Values{
		"keyword": {"AR6140"}, "ip": {"192.0.2.10"}, "mac": {"00:46:4b:12:34:56"}, "vlan": {"120"}, "brand": {"Huawei"}, "model": {"AR6140"}, "role": {"router"}, "status": {"confirmed"}, "source": {"lldp"}, "confidence_min": {"80"}, "confidence_max": {"100"}, "first_seen_from": {"2026-09-24T00:00:00Z"}, "first_seen_to": {"2026-09-24T23:59:59Z"}, "last_seen_from": {"2026-09-24T00:00:00Z"}, "last_seen_to": {"2026-09-24T23:59:59Z"}, "infrastructure": {"false"}, "limit": {"25"}, "cursor": {"50"},
	}
	query, err := routerObservationQuery(values)
	if err != nil {
		t.Fatal(err)
	}
	if query.Keyword != "AR6140" || query.IP != "192.0.2.10" || query.MAC != "00:46:4b:12:34:56" || query.VLAN != "120" || query.Brand != "Huawei" || query.Model != "AR6140" || query.Role != "router" || query.Status != "confirmed" || query.Source != "lldp" || query.ConfidenceMin == nil || *query.ConfidenceMin != 80 || query.ConfidenceMax == nil || *query.ConfidenceMax != 100 || query.Infrastructure == nil || *query.Infrastructure || query.Limit != 25 || query.Cursor != 50 {
		t.Fatalf("filters not preserved: %+v", query)
	}
}

func TestRouterObservationQueryRejectsInvalidBounds(t *testing.T) {
	for _, values := range []url.Values{
		{"status": {"blocked"}},
		{"confidence_min": {"101"}},
		{"confidence_min": {"80"}, "confidence_max": {"60"}},
		{"infrastructure": {"sometimes"}},
	} {
		if _, err := routerObservationQuery(values); err == nil {
			t.Fatalf("expected invalid query to fail: %v", values)
		}
	}
}
