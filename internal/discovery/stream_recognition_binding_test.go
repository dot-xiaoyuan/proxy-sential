package discovery

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRecognitionBindingSaturationDoesNotPublishPartialOwners(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	dirty := newStreamRecognitionDirty()
	dirty.add(nil, streamDiscoveryFact{IP: "192.0.2.1", RecognitionFields: map[string]string{"mdns_model": "Mac14,15"}})
	mock.ExpectQuery("WITH scopes AS").WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"mac", "saturated"}).AddRow("02:00:00:00:00:01", true))
	if err := dirty.mark(context.Background(), tx); err == nil || !strings.Contains(err.Error(), "budget exceeded") {
		t.Fatalf("partial binding result was silently published: %v", err)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
