package store

import "testing"

func TestEventSampleDecodePreservesCampus(t *testing.T) {
	events, err := decodeEventRows([]byte(`{"timestamp":"2026-09-16 05:00:00","event_id":"scope","subject_ip":"192.0.2.1","campus_id":"test190","payload_json":"{\"access_domain\":\"srun190\"}"}`))
	if err != nil || len(events) != 1 {
		t.Fatal(err)
	}
	if events[0].Subject["campus_id"] != "test190" || events[0].Payload["access_domain"] != "srun190" {
		t.Fatal("event scope lost", events[0])
	}
}
