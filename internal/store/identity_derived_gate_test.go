package store

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIdentityDerivedGateReportsQueryFailureAndKeepsWorkDeferred(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	store := &DBStore{pg: &PostgresStore{db: db, sensorID: "sensor-a"}}
	for i := 0; i < 2; i++ {
		mock.ExpectQuery(`SELECT EXISTS`).WithArgs("sensor-a").WillReturnError(errors.New("database unavailable"))
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		deferred := store.deferIdentityDerivedWorkWithQuota(ctx)
		cancel()
		if !deferred {
			t.Fatal("failed realtime check must not silently admit derived work")
		}
	}
	if got := strings.Count(output.String(), "identity derived priority check failed"); got != 1 {
		t.Fatalf("expected one rate-limited error report, got %d in %q", got, output.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
