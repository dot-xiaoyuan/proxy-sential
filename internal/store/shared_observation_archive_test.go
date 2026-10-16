package store

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/sharedaccess"
)

// A failed write, missing original or failed read-back must leave the hot copy.
func TestSharedArchiveVerifiesBeforeRemovingHotCopy(t *testing.T) {
	for _, mode := range []string{"ok", "missing_original", "write_failed", "checksum_changed"} {
		t.Run(mode, func(t *testing.T) {
			scope, cfg, events, now := handshakeReplayFixture()
			window, assessment, err := buildHandshakeObservation(scope, cfg, events, now)
			if err != nil {
				t.Fatal(err)
			}
			decision := sharedaccess.NewObservationDecision(window, sharedaccess.Result{State: "insufficient"}, cfg, now)
			raw, _ := json.Marshal(decision)
			item, _ := json.Marshal(assessment)
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec("UPDATE shared_observation_executions SET state").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("SELECT d.document").WillReturnRows(sqlmock.NewRows([]string{"document", "observation", "first_received_at"}).AddRow(raw, item, now.Add(-31*24*time.Hour)))
			stored := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				query := string(body)
				switch {
				case strings.HasPrefix(query, "SELECT formatDateTime"):
					if mode != "missing_original" {
						for _, event := range events {
							_ = json.NewEncoder(w).Encode(event)
						}
					}
				case strings.HasPrefix(query, "INSERT INTO shared_observation_archive_v1"):
					if mode == "write_failed" {
						http.Error(w, "unavailable", 500)
						return
					}
					var record struct {
						Document string `json:"document"`
					}
					if e := json.Unmarshal(body[strings.IndexByte(query, '\n')+1:], &record); e != nil {
						t.Error(e)
					}
					stored = record.Document
				case strings.HasPrefix(query, "SELECT document"):
					if mode == "checksum_changed" {
						stored = "{}"
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"document": stored})
				default:
					t.Errorf("unexpected archive query: %.80s", query)
					http.Error(w, "unexpected", 500)
				}
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "ok" {
				mock.ExpectExec("INSERT INTO shared_observation_archive_receipts").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("DELETE FROM policy_decision_records").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("DELETE FROM shared_observation_executions").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("DELETE FROM shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}
			did, err := (&DBStore{pg: &PostgresStore{db: db}, ch: ch}).ArchiveSharedObservation(context.Background())
			if !did || (err != nil) != (mode != "ok") {
				t.Fatalf("did=%v err=%v", did, err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
