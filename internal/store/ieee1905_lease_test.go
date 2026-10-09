package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIEEE1905LeaseResolutionIsCachedAndErrorsAbort(t *testing.T) {
	for _, mode := range []string{"valid", "empty", "failure"} {
		t.Run(mode, func(t *testing.T) {
			at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
			row := ieee1905AssociationRow{Timestamp: at.Format(time.RFC3339Nano), EventID: "a", SensorID: "office", CampusID: "campus", GatewayMAC: "20:3a:eb:e9:de:10", ClientMAC: "02:00:00:00:00:01", BSSID: "02:00:00:00:00:02", State: "joined", Source: "packet-sidecar"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(row)
				other := row
				other.ClientMAC = "02:00:00:00:00:03"
				other.EventID = "b"
				json.NewEncoder(w).Encode(other)
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			expected := errors.New("lease storage unavailable")
			lookup := mock.ExpectQuery("SELECT DISTINCT host").WithArgs("office", "campus", "mac:20:3a:eb:e9:de:10", at)
			if mode == "failure" {
				lookup.WillReturnError(expected)
			} else {
				rows := sqlmock.NewRows([]string{"ip"})
				if mode == "valid" {
					rows.AddRow("192.0.2.22")
				}
				lookup.WillReturnRows(rows)
				// A single lookup serves both clients, including the no-address result.
				for i := 0; i < 2; i++ {
					mock.ExpectExec("INSERT INTO ieee1905_client_associations").WillReturnResult(sqlmock.NewResult(0, 1))
				}
			}
			err = (&DBStore{pg: &PostgresStore{db: db}, ch: ch}).syncIEEE1905Associations(context.Background(), "office", at.Add(-time.Minute), at.Add(time.Minute))
			if mode == "failure" && !errors.Is(err, expected) {
				t.Fatalf("lease failure swallowed: %v", err)
			}
			if mode != "failure" && err != nil {
				t.Fatal(err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
