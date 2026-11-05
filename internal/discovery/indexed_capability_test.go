package discovery

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDumbCapabilityFilterMatchesServiceAndRoutingEvidence(t *testing.T) {
	for _, tc := range []struct {
		caps []string
		want bool
	}{
		{[]string{"printing"}, true},
		{[]string{"network_video"}, true},
		{[]string{"routing"}, true},
		{[]string{"arp"}, false},
		{nil, false},
	} {
		if got := matchesDeviceCapability(tc.caps, "dumb"); got != tc.want {
			t.Fatalf("caps=%v dumb=%t, want %t", tc.caps, got, tc.want)
		}
	}
	if !matchesDeviceCapability([]string{"printing"}, "printing") || matchesDeviceCapability([]string{"printing"}, "scanning") {
		t.Fatal("ordinary capability filters must remain exact")
	}
}

func TestIndexedDumbFilterRunsBeforeCandidateLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`(?s)GROUP BY device_key\s+HAVING bool_or\(coalesce\(data->'capabilities'.*LIMIT`).WillReturnRows(
		sqlmock.NewRows([]string{"device_key", "data", "endpoint_id", "role", "confidence", "conflict"}),
	)
	_, err = (Repository{DB: db}).DevicesIndexed(context.Background(), DeviceQuery{Mode: "passive", Capability: "dumb", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
