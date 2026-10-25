package discovery

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestExpiredDiscoveryLeaseCannotPublish(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m.ExpectBegin()
	m.ExpectQuery("SELECT lease_token").WithArgs("batch", "old-token", 50).WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(false))
	m.ExpectRollback()
	r := Repository{DB: db}
	if _, err = r.beginDiscoveryPublish(context.Background(), discoveryClaim{ID: "batch", Token: "old-token", Offset: 50}); !errors.Is(err, ErrDiscoveryLeaseLost) {
		t.Fatalf("got %v", err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryClaimHasNoTransactionDuringArchive(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// No ExpectBegin: an archive failure must occur outside a database transaction.
	m.ExpectQuery("UPDATE discovery_batch_work").WithArgs("realtime", sqlmock.AnyArg(), "").WillReturnRows(sqlmock.NewRows([]string{"id", "events", "offset", "archived", "accepted", "source", "selected_count"}).AddRow("batch", []byte(`[{"event_id":"one"}]`), 0, false, time.Now(), "discovery-v2", nil))
	m.ExpectExec("UPDATE discovery_batch_work SET attempts").WillReturnResult(sqlmock.NewResult(0, 1))
	sentinel := errors.New("archive unavailable")
	r := Repository{DB: db, Archive: func(context.Context, []normalized.Event) error { return sentinel }}
	worked, err := r.ProcessDiscoveryBatch(context.Background())
	if !worked || !errors.Is(err, sentinel) {
		t.Fatalf("%v %v", worked, err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryClaimReadsOnlyCurrentSegment(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	part := []normalized.Event{{EventID: "first", Observer: map[string]any{"sensor_id": "sensor"}}}
	raw, err := EncodeDiscoveryBatch(part)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("UPDATE discovery_batch_work").WithArgs("realtime", sqlmock.AnyArg(), "").WillReturnRows(
		sqlmock.NewRows([]string{"id", "events", "offset", "archived", "accepted", "source", "selected_count"}).AddRow("batch", nil, 0, false, time.Now(), "discovery-v2", 51))
	mock.ExpectQuery("SELECT first_offset,event_count,byte_count,content_sha256,events,archive_verified_at IS NOT NULL").WithArgs("batch", 0).WillReturnRows(
		sqlmock.NewRows([]string{"first_offset", "event_count", "byte_count", "content_sha256", "events", "archived"}).AddRow(0, 1, len(raw), contentHash(part), raw, false))
	claim, err := (Repository{DB: db}).claimDiscovery(context.Background(), "realtime")
	if err != nil || !claim.Segmented || claim.Total != 51 || claim.SegmentCount != 1 || string(claim.Raw) != string(raw) {
		t.Fatalf("claim=%+v err=%v", claim, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
