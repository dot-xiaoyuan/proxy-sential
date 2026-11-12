package discovery

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// Latest rows are keyed by source and service, so multiple rows may carry the
// same observation ID while retaining different payloads and identities.
func TestIndexedPageReadsSelectedPayloadWhenObservationIDRepeats(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := sqlmock.NewRows([]string{"identity_key", "device_key", "data", "endpoint_id", "role", "confidence", "conflict", "category"})
	now := time.Now().UTC()
	for _, mac := range []string{"00:11:22:33:44:55", "00:11:22:33:44:66"} {
		payload, err := json.Marshal(Observation{ID: "shared-observation-id", Origin: "arp", Node: "campus-204", MAC: mac, ObservedAt: now, ValidUntil: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		rows.AddRow(mac, "shared-device-key", payload, "", "", 0, false, "identity_only")
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT c.identity_key,c.device_key,l.data,")).WillReturnRows(rows)
	page, err := (Repository{DB: db}).DevicesIndexed(context.Background(), DeviceQuery{Mode: "passive", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]DeviceView)
	if len(items) != 2 || items[0].MAC == items[1].MAC {
		t.Fatalf("same observation ID mixed distinct MAC identities: %+v", items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
