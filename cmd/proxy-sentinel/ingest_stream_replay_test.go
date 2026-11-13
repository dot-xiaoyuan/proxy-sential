package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/streamlog"
)

func replayFixture(t *testing.T) (*streamlog.Journal, string, string, []string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "flow-syn.jsonl")
	prefix := []byte("old-confirmed\n")
	first := []byte("{\"event_id\":\"producer-one\"}\n")
	second := []byte("{\"event_id\":\"producer-two\"}\n")
	suffix := []byte("{\"event_id\":\"producer-three\"}\n")
	if err := os.WriteFile(source, append(append(append(append([]byte{}, prefix...), first...), second...), suffix...), 0o600); err != nil {
		t.Fatal(err)
	}
	recoveryDir := filepath.Join(root, "recovery")
	if err := os.Mkdir(recoveryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	recovery := filepath.Join(recoveryDir, "flow-syn.jsonl.1")
	if err := os.Link(source, recovery); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(source, source+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new-live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(recovery)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "false")
	fileID := realtime.FileIdentity(source, info)
	j, err := streamlog.Open(filepath.Join(root, "old-journal"))
	if err != nil {
		t.Fatal(err)
	}
	cursor := streamlog.SourceCursor{Epoch: "flow-old", Source: "device-signals", Path: source,
		FileID: fileID, Offset: int64(len(prefix)), ParserVersion: deviceSignalStreamParser}
	if err := j.StartFreshSource(cursor); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, 2)
	start := int64(len(prefix))
	for index, raw := range [][]byte{first, second} {
		end := start + int64(len(raw))
		sum := sha256.Sum256(raw)
		event := normalized.Event{EventID: "stream-" + string(rune('a'+index)), Source: "flow-syn-sidecar",
			SourceEventType: "syn_attempt", Type: "flow", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
		segment := streamlog.Segment{Epoch: cursor.Epoch, Source: cursor.Source, SourcePath: source,
			FileID: fileID, PreviousFileID: fileID, PreviousOffset: start, StartOffset: start, EndOffset: end,
			ParserVersion: deviceSignalStreamParser, RawIsStandardEvents: true, Raw: raw,
			RawSHA256: hex.EncodeToString(sum[:]), ArchiveMonth: time.Now().UTC().Format("200601"),
			AcceptedAt: time.Now().UTC(), Events: []normalized.Event{event}}
		id, err := j.Append(segment)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.CommitSource(cursor.Source, source, id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		start = end
	}
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	return j, source, recovery, ids
}

func TestRecordFlowReplayKeepsOldWorkAndAuditsNewStart(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	plan := flowReplayPlan{OldEpoch: "old", NewEpoch: "new", SourcePath: "/signals/flow-syn.jsonl",
		OldJournal: "/old", OldFileID: "legacy", BirthFileID: "birth", OldCursorOffset: 20,
		ReplayStart: 10, ReplayFileEnd: 30, ReplayFileSHA256: strings.Repeat("a", 64),
		ReplayRangeSHA256: strings.Repeat("b", 64), PendingSHA256: strings.Repeat("c", 64),
		PlanSHA256: strings.Repeat("d", 64), PendingEvents: 2,
		Pending: []flowReplayPending{{ID: "segment-one", Start: 10, End: 20, Events: 2,
			SegmentSHA256: strings.Repeat("e", 64)}}}
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT state,sensor_id FROM stream_source_cutovers").
		WithArgs("old", plan.SourcePath).WillReturnRows(sqlmock.NewRows([]string{"state", "sensor_id"}).AddRow("active", "sensor"))
	mock.ExpectQuery("SELECT r.plan_sha256,c.state FROM stream_source_replays").
		WithArgs("new", plan.SourcePath).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("SELECT count\\(\\*\\) FROM stream_source_cutovers").
		WithArgs(plan.SourcePath).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectExec("UPDATE stream_source_cutovers SET state='closed'").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO stream_source_cutovers").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO stream_source_replays").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO stream_discard_manifest").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := recordFlowReplay(context.Background(), db, plan, "sensor", strings.Repeat("a", 64), "release", "replay-id", "/new"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecordFlowReplayRejectsDifferentPreparedPlan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	plan := flowReplayPlan{OldEpoch: "old", NewEpoch: "new", SourcePath: "/signals/flow-syn.jsonl", PlanSHA256: strings.Repeat("a", 64)}
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT state,sensor_id FROM stream_source_cutovers").
		WithArgs("old", plan.SourcePath).WillReturnRows(sqlmock.NewRows([]string{"state", "sensor_id"}).AddRow("closed", "sensor"))
	mock.ExpectQuery("SELECT r.plan_sha256,c.state FROM stream_source_replays").
		WithArgs("new", plan.SourcePath).WillReturnRows(sqlmock.NewRows([]string{"plan_sha256", "state"}).AddRow(strings.Repeat("b", 64), "prepared"))
	mock.ExpectRollback()
	if err := recordFlowReplay(context.Background(), db, plan, "sensor", "scope", "release", "replay-id", "/new"); err == nil {
		t.Fatal("changed plan re-opened a closed old source")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFlowReplayPlansUnfinishedSegmentsAndAllLaterSourceBytes(t *testing.T) {
	j, source, recovery, ids := replayFixture(t)
	plan, err := inspectFlowReplay(j, source, recovery, "flow-old", "flow-birth-new",
		"/new/journal", "sensor", strings.Repeat("a", 64), "old-release", "replay-one")
	if err != nil {
		t.Fatal(err)
	}
	if plan.ReplayStart != int64(len("old-confirmed\n")) || plan.OldCursorOffset != plan.Pending[1].End ||
		plan.ReplayFileEnd <= plan.OldCursorOffset || plan.PendingEvents != 2 || plan.ReplayRecords != 3 ||
		len(plan.Pending) != 2 || plan.Pending[0].ID != ids[0] || plan.Pending[1].ID != ids[1] ||
		!strings.Contains(plan.BirthFileID, ":birth:") || len(plan.PlanSHA256) != 64 {
		t.Fatalf("replay plan omitted a pending or unread range: %+v", plan)
	}
	again, err := inspectFlowReplay(j, source, recovery, "flow-old", "flow-birth-new",
		"/new/journal", "sensor", strings.Repeat("a", 64), "old-release", "replay-one")
	if err != nil || again.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("plan digest changed without input change: %v", err)
	}
}

func TestFlowReplayRejectsChangedProtectedBytes(t *testing.T) {
	j, source, recovery, _ := replayFixture(t)
	f, err := os.OpenFile(recovery, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("X"), int64(len("old-confirmed\n"))); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := inspectFlowReplay(j, source, recovery, "flow-old", "flow-birth-new",
		"/new/journal", "sensor", strings.Repeat("a", 64), "old-release", "replay-one"); err == nil {
		t.Fatal("changed source was accepted as the pending journal")
	}
}

func TestFlowReplayRejectsAlreadyArchivedSegment(t *testing.T) {
	j, source, recovery, ids := replayFixture(t)
	if err := j.Ack(ids[0], streamlog.Archive); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectFlowReplay(j, source, recovery, "flow-old", "flow-birth-new",
		"/new/journal", "sensor", strings.Repeat("a", 64), "old-release", "replay-one"); err == nil {
		t.Fatal("already archived source was accepted for replay")
	}
}
