package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// Repeated mDNS hostname advertisements accumulate for months; the owner
// lookup only needs records that could still be valid at the observation
// time. Bound the scan to one day so a busy hostname cannot sort the full
// history into a temporary file.
func TestMDNSServiceOwnersBoundsLookupToRecentDay(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("(?s)device_name_evidence.*observed_at>=.4 - interval '24 hours'.*").
		WithArgs("campus-204", "campus-204", "xuyang-5.local", now).
		WillReturnRows(sqlmock.NewRows([]string{"evidence"}))
	owners, err := (&PostgresStore{db: db}).mdnsServiceOwners(context.Background(), DeviceNameEvidence{
		SensorID: "campus-204", CampusID: "campus-204", ServiceTarget: "xuyang-5.local", ObservedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 0 {
		t.Fatalf("no evidence rows must produce no owners: %v", owners)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
