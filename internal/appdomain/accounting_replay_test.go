package appdomain

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestAccountingReplayBaseline(t *testing.T) {
	raw, err := os.ReadFile("testdata/accounting.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []Observation
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	q := Query{From: time.Date(2026, 9, 8, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC), CampusID: "a"}
	r := Aggregate(rows, q)
	if r.ObservationCount != 7 || r.DNSObservations != 1 || r.UnknownObservations != 2 || r.MissingConnectionObservations != 1 || r.MultiApplication.ConnectionCount != 1 || *r.MultiApplication.UploadBytes != 50 || r.Unknown.ConnectionCount != 0 || r.Unknown.UploadBytes != nil || r.Unknown.MissingMeterConnections != 0 || r.Versions["v1"] != 7 {
		t.Fatalf("bad replay: %+v", r)
	}
	if len(r.Items) != 2 || r.Items[0].ApplicationID != "wx" || r.Items[0].ConnectionCount != 1 || *r.Items[0].UploadBytes != 30 || r.Items[0].TerminalCount != 1 || r.Items[1].UploadBytes != nil {
		t.Fatalf("items: %+v", r.Items)
	}
	q.ApplicationID = "qq"
	filtered := Aggregate(rows, q)
	if len(filtered.Items) != 1 || filtered.Items[0].ConnectionCount != 0 || filtered.MultiApplication.ConnectionCount != 1 || *filtered.MultiApplication.UploadBytes != 50 {
		t.Fatalf("early app filter corrupted connection: %+v", filtered)
	}
}
