package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"proxy-sentinel/internal/normalized"
)

func TestSplitIdentityInboxFragmentsKeepsOrderAndBounds(t *testing.T) {
	events := make([]normalized.Event, 121)
	for i := range events {
		events[i].EventID = strings.Repeat("x", 4000) + string(rune(i+1))
	}
	fragments, err := splitIdentityInboxFragments(events)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) < 3 {
		t.Fatalf("expected multiple bounded fragments, got %d", len(fragments))
	}
	ordinal := 0
	for _, fragment := range fragments {
		if fragment.FirstOrdinal != ordinal || fragment.Count < 1 || fragment.Count > identityInboxFragmentMaxEvents || len(fragment.JSON) > identityInboxFragmentMaxBytes {
			t.Fatalf("invalid fragment at %d: %+v", ordinal, fragment)
		}
		var decoded []normalized.Event
		if err := json.Unmarshal(fragment.JSON, &decoded); err != nil {
			t.Fatal(err)
		}
		for _, event := range decoded {
			if event.EventID != events[ordinal].EventID {
				t.Fatalf("event order changed at %d", ordinal)
			}
			ordinal++
		}
	}
	if ordinal != len(events) {
		t.Fatalf("got %d records, want %d", ordinal, len(events))
	}
}

func TestClaimIdentityInboxReadsOnlyRemainingFragmentRecords(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS", "false")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accepted := time.Date(2026, 10, 24, 15, 0, 0, 0, time.UTC)
	first, _ := json.Marshal([]normalized.Event{{EventID: "already-applied"}, {EventID: "remaining-1"}})
	second, _ := json.Marshal([]normalized.Event{{EventID: "remaining-2"}})
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT scope_key,current_generation,lease_epoch\+1`).WithArgs("sensor").WillReturnRows(sqlmock.NewRows([]string{"scope_key", "current_generation", "epoch", "sequence", "snapshot_at"}).AddRow("scope", "generation", int64(7), int64(3), nil))
	mock.ExpectExec(`UPDATE identity_pipeline_scopes SET lease_epoch`).WithArgs("scope", int64(7), identityInboxLease.Seconds()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery(`WITH candidates AS MATERIALIZED`).WithArgs("scope", int64(3), 2).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "sequence", "processed_offset", "records_emitted", "payload_format", "first_ordinal", "payload", "accepted_at"}).AddRow("batch", int64(3), 1, 3, "fragments", 0, first, accepted).AddRow("batch", int64(3), 1, 3, "fragments", 2, second, accepted))
	work, err := (&PostgresStore{db: db}).claimIdentityInbox(context.Background(), "sensor", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Batches) != 1 || work.Batches[0].Offset != 1 || work.Batches[0].Count != 2 || len(work.Events) != 2 || work.Events[0].EventID != "remaining-1" || work.Events[1].EventID != "remaining-2" {
		t.Fatalf("unexpected bounded claim: %+v", work)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSplitIdentityInboxFragmentsRejectsOversizedEvent(t *testing.T) {
	events := []normalized.Event{{EventID: strings.Repeat("x", identityInboxFragmentMaxBytes)}}
	if _, err := splitIdentityInboxFragments(events); err == nil {
		t.Fatal("oversized event must not create an unbounded fragment")
	}
}
