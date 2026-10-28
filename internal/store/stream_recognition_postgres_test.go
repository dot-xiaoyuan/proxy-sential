package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStreamRecognitionHintKeepsBindingAndExpiry(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(passthroughConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	until := now.Add(time.Minute)
	mock.ExpectQuery("WITH candidates AS").WithArgs(sqlmock.AnyArg(), now).
		WillReturnRows(sqlmock.NewRows([]string{"id", "value", "field", "protocol", "event", "observed", "until", "association"}).
			AddRow("endpoint-a", "Mac14,15", "mdns_model", "dns_sd", "event-a", now, until, "unique_stream_binding"))
	s := &PostgresStore{db: db}
	hints, err := s.StreamDiscoveryRecognitionHints(context.Background(), []string{"endpoint-a"}, now)
	if err != nil {
		t.Fatal(err)
	}
	signals := passiveRecognitionSignals(hints["endpoint-a"])
	if len(signals) != 1 || signals[0].Association != "unique_stream_binding" || !signals[0].ValidUntil.Equal(until) || signals[0].EventID != "event-a" {
		t.Fatalf("stream evidence lost lifetime or attribution: %+v", signals)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
