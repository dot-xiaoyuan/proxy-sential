package netscan

import (
	"fmt"
	"testing"
	"time"
)

func TestReplayDenseAndSparse(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	zones := []Zone{{ID: "dense", CampusID: "c", CIDR: "10.1.0.0/24"}}
	for i := 1; i <= 50; i++ {
		zones = append(zones, Zone{ID: fmt.Sprintf("z%d", i), CampusID: "c", CIDR: fmt.Sprintf("10.2.%d.0/24", i)})
	}
	var attempts []Attempt
	for i := 1; i <= 50; i++ {
		attempts = append(attempts, Attempt{SensorID: "s", CampusID: "c", ConnectionID: fmt.Sprintf("d%d", i), SourceIP: "10.9.0.1", DestinationIP: fmt.Sprintf("10.1.0.%d", i), DestinationPort: 445, State: Failed, At: now.Add(-time.Minute)})
		attempts = append(attempts, Attempt{SensorID: "s", CampusID: "c", ConnectionID: fmt.Sprintf("s%d", i), SourceIP: "10.9.0.2", DestinationIP: fmt.Sprintf("10.2.%d.1", i), DestinationPort: 445, State: Failed, At: now.Add(-time.Minute)})
	}
	// A repeated protocol event cannot increase either threshold.
	attempts = append(attempts, attempts[0])
	unknownCopy := attempts[0]
	unknownCopy.State = Unknown
	unknownCopy.At = now
	attempts = append(attempts, unknownCopy)
	got := Evaluate(Config{Enabled: true}, zones, attempts, now)
	if len(got) != 2 || got[0].Mode != Dense && got[1].Mode != Dense || got[0].Mode != Sparse && got[1].Mode != Sparse {
		t.Fatalf("findings=%+v", got)
	}
	for _, item := range got {
		if item.Attempts != 50 || item.Failed != 50 {
			t.Fatalf("duplicate counted: %+v", item)
		}
	}
}

func TestReplayRejectsNormalTrafficAndMissingOutcome(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	zones := []Zone{{ID: "z", CampusID: "c", CIDR: "10.1.0.0/24"}, {ID: "specific", CampusID: "c", CIDR: "10.1.0.0/25"}}
	var attempts []Attempt
	for i := 1; i <= 50; i++ {
		attempts = append(attempts, Attempt{SensorID: "s", CampusID: "c", ConnectionID: fmt.Sprint(i), SourceIP: "10.9.0.1", DestinationIP: fmt.Sprintf("10.1.0.%d", i), DestinationPort: 443, State: Unknown, At: now.Add(-time.Minute)})
	}
	if got := Evaluate(Config{Enabled: true}, zones, attempts, now); len(got) != 0 {
		t.Fatalf("unknown outcome fired: %+v", got)
	}
	for i := range attempts {
		attempts[i].State = Succeeded
	}
	if got := Evaluate(Config{Enabled: true}, zones, attempts, now); len(got) != 0 {
		t.Fatalf("normal traffic fired: %+v", got)
	}
	for i := range attempts {
		attempts[i].State = Failed
	}
	if got := Evaluate(Config{Enabled: true, ExcludedSourceCIDRs: []string{"10.9.0.0/24"}}, zones, attempts, now); len(got) != 0 {
		t.Fatalf("excluded scanner fired: %+v", got)
	}
	got := Evaluate(Config{Enabled: true}, zones, attempts, now)
	if len(got) != 1 || got[0].ZoneIDs[0] != "specific" {
		t.Fatalf("longest prefix lost: %+v", got)
	}
}

func TestReplayDenseRequiresAdjacentAddresses(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	zones := []Zone{{ID: "z", CampusID: "c", CIDR: "10.1.0.0/24"}}
	var attempts []Attempt
	for i := 1; i <= 50; i++ {
		attempts = append(attempts, Attempt{SensorID: "s", CampusID: "c", ConnectionID: fmt.Sprint(i), SourceIP: "10.9.0.1", DestinationIP: fmt.Sprintf("10.1.0.%d", 2*i), DestinationPort: 445, State: Failed, At: now.Add(-time.Minute)})
	}
	if got := Evaluate(Config{Enabled: true}, zones, attempts, now); len(got) != 0 {
		t.Fatalf("nonadjacent access fired: %+v", got)
	}
}
