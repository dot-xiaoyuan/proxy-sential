package main

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/streamlog"
)

type cancellationPayload struct{ t *testing.T }

func (p cancellationPayload) Match(value driver.Value) bool {
	raw, ok := value.([]byte)
	if !ok {
		return false
	}
	var entries []zeekDiscardEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		p.t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.LegacyKind] = true
		if e.LegacyKind == "stream_pending_segment" && (e.LegacyStatus != "cancelled_unprocessed" || e.UnprocessedRecords != 7 || e.UnprocessedBytes != 100) {
			return false
		}
	}
	return seen["stream_pending_segment"] && seen["stream_pending_lane"] && seen["stream_retirement_manifest"]
}

func TestPendingStreamCancellationPreviewAtomicityAndIdempotence(t *testing.T) {
	cutoff := time.Now().UTC().Truncate(time.Second)
	cursor := streamlog.SourceCursor{Epoch: "old", Source: "device-signals", Path: "/signals/ttl.jsonl", FileID: "file", ParserVersion: "device-v1", Offset: 100}
	segments := []streamlog.CancellationSegment{{ID: strings.Repeat("a", 64), ContentSHA256: strings.Repeat("b", 64), FileID: "file", EndOffset: 100, Events: 7, AcceptedAt: cutoff.Add(-time.Second), Acks: map[streamlog.Lane]streamlog.Status{streamlog.Archive: streamlog.Acked, streamlog.Search: streamlog.Attempted, streamlog.Projection: streamlog.Acked}}}
	var manifest string
	for _, scenario := range []string{"preview", "audit-failure", "shared-missing", "apply", "retry", "different-id", "different-cutoff"} {
		t.Run(scenario, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			apply := scenario != "preview"
			closed := scenario == "retry" || scenario == "different-id" || scenario == "different-cutoff"
			state := "active"
			if closed {
				state = "closed"
			}
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT sensor_id,parser_version,cancel_manifest_sha256,state`).WithArgs(cursor.Epoch, cursor.Source, cursor.Path).WillReturnRows(sqlmock.NewRows([]string{"sensor", "parser", "manifest", "state"}).AddRow("sensor", cursor.ParserVersion, strings.Repeat("c", 64), state))
			rows := sqlmock.NewRows([]string{"ref", "hash"})
			if closed {
				rows.AddRow("cancel", manifest)
			}
			mock.ExpectQuery(`SELECT legacy_reference,content_sha256`).WithArgs(cursor.Epoch, cursor.Source, cursor.Path).WillReturnRows(rows)
			if apply && !closed {
				ex := mock.ExpectExec(`INSERT INTO stream_discard_manifest`).WithArgs(cursor.Epoch, cursor.Source, cursor.Path, cancellationPayload{t})
				if scenario == "audit-failure" {
					ex.WillReturnError(errors.New("audit failed"))
				} else {
					ex.WillReturnResult(sqlmock.NewResult(0, 9))
					n := int64(1)
					if scenario == "shared-missing" {
						n = 0
					}
					mock.ExpectExec(`UPDATE stream_shared_source_cutovers`).WithArgs("sensor", cursor.Epoch, cursor.Path).WillReturnResult(sqlmock.NewResult(0, n))
					if n == 1 {
						mock.ExpectExec(`UPDATE stream_source_cutovers`).WithArgs(cursor.Epoch, cursor.Source, cursor.Path).WillReturnResult(sqlmock.NewResult(0, 1))
					}
				}
			}
			wantError := scenario == "audit-failure" || scenario == "shared-missing" || strings.HasPrefix(scenario, "different")
			if wantError {
				mock.ExpectRollback()
			} else {
				mock.ExpectCommit()
			}
			id, at := "cancel", cutoff
			if scenario == "different-id" {
				id = "another"
			}
			if scenario == "different-cutoff" {
				at = at.Add(-time.Second)
			}
			got, err := auditPendingStreamCancellation(context.Background(), db, "sensor", id, "用户要求取消旧待办", at, cursor, segments, apply)
			if wantError != (err != nil) {
				t.Fatalf("manifest=%s err=%v", got, err)
			}
			if err == nil {
				if len(got) != 64 {
					t.Fatalf("invalid manifest %q", got)
				}
				if manifest == "" {
					manifest = got
				} else if got != manifest {
					t.Fatal("preview, apply and retry changed immutable manifest")
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
