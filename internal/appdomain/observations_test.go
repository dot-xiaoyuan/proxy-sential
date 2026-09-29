package appdomain

import (
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func fixtureEvent(id, typ, host, conn string, up any) normalized.Event {
	payload := map[string]any{"host": host, "sni": host, "query": host}
	return normalized.Event{EventID: id, Timestamp: "2026-09-08T10:00:00Z", Type: typ, Subject: map[string]any{"ip": "10.0.0.1", "campus_id": "a"}, Observer: map[string]any{"sensor_id": "s"}, Flow: map[string]any{"connection_id": conn, "bytes_toserver": up, "bytes_toclient": float64(10)}, Payload: payload}
}
func TestAggregateConnectionAccounting(t *testing.T) {
	b, _ := Verify(testBundle(t, "v1"))
	es := []normalized.Event{fixtureEvent("1", "tls", "a.weixin.qq.com", "c1", float64(20)), fixtureEvent("2", "flow", "", "c1", float64(30)), fixtureEvent("3", "dns", "bilibili.com", "dns", float64(999)), fixtureEvent("4", "http", "bilibili.com", "", nil)}
	obs := []Observation{}
	for _, e := range es {
		obs = append(obs, Observe(e, b))
	}
	obs = append(obs, obs[0])
	q := Query{From: time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)}
	r := Aggregate(obs, q)
	if len(r.Items) != 2 || r.Items[0].UploadBytes == nil || *r.Items[0].UploadBytes != 30 || r.Items[0].ConnectionCount != 1 || r.DNSObservations != 1 || r.MissingConnectionObservations != 1 {
		t.Fatalf("%+v items=%+v", r, r.Items)
	}
	obs = append(obs, Observe(fixtureEvent("5", "http", "bilibili.com", "c1", float64(5)), b))
	r = Aggregate(obs, q)
	if r.MultiApplication.ConnectionCount != 1 || r.MultiApplication.UploadBytes == nil || *r.MultiApplication.UploadBytes != 30 {
		t.Fatalf("%+v", r)
	}
	for _, it := range r.Items {
		if it.UploadBytes != nil {
			t.Fatalf("allocated multi-app bytes: %+v", it)
		}
	}
}

func TestHistoricalWindowDoesNotUseFutureCounters(t *testing.T) {
	b, _ := Verify(testBundle(t, "v1"))
	a := Observe(fixtureEvent("1", "tls", "a.weixin.qq.com", "c", float64(20)), b)
	future := Observe(fixtureEvent("2", "flow", "", "c", float64(1000)), b)
	future.Timestamp = "2026-09-09T10:00:00Z"
	q := Query{From: time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)}
	r := Aggregate([]Observation{future, a}, q)
	if len(r.Items) != 1 || r.Items[0].UploadBytes == nil || *r.Items[0].UploadBytes != 20 {
		t.Fatalf("future counter leaked: %+v", r)
	}
}

func TestConnectionUsesEarlierEvidenceWithoutCountingItInWindow(t *testing.T) {
	b, _ := Verify(testBundle(t, "v1"))
	early := Observe(fixtureEvent("1", "tls", "a.weixin.qq.com", "c", float64(20)), b)
	early.Timestamp = "2026-09-08T08:00:00Z"
	flow := Observe(fixtureEvent("2", "flow", "", "c", float64(30)), b)
	q := Query{From: time.Date(2026, 9, 8, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC)}
	r := Aggregate([]Observation{early, flow}, q)
	if len(r.Items) != 1 || r.Items[0].ObservationCount != 0 || r.Items[0].TerminalCount != 1 || r.Items[0].LastSeen != flow.Timestamp || *r.Items[0].UploadBytes != 30 {
		t.Fatalf("bad historical association: %+v", r.Items)
	}
}
