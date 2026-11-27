package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

func TestSRunIdentityPollComparesLoginGenerations(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Microsecond)
	makeSnapshot := func(stamp time.Time, account, generation string) store.IdentitySnapshot {
		t.Helper()
		count := 1
		snap, err := prepareIdentitySnapshot(identitySnapshotRequest{
			IdentityScope: store.IdentityScope{Source: "srun4k:replay", SensorID: "replay"},
			ObservedAt:    stamp, IntervalSeconds: 21600, Complete: true, ExpectedCount: &count,
			Records: []map[string]string{{"session_id": "s", "ip": "192.168.0.57", "account_id": account, "source_login_generation": generation}},
		}, "replay", stamp)
		if err != nil {
			t.Fatal(err)
		}
		return snap
	}
	old := makeSnapshot(at, "yuantong", "one")
	for _, tc := range []struct {
		name     string
		snapshot store.IdentitySnapshot
		same     bool
	}{
		{"unchanged_next_poll", makeSnapshot(at.Add(time.Minute), "yuantong", "one"), true},
		{"relogin_same_ip", makeSnapshot(at.Add(time.Minute), "yuantong", "two"), false},
		{"new_account", makeSnapshot(at.Add(time.Minute), "another", "one"), false},
		{"logout_empty_inventory", store.IdentitySnapshot{IdentityScope: old.IdentityScope, IntervalSeconds: 21600, Events: []normalized.Event{}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			same, err := sameSRunIdentityMembers(context.Background(), old, tc.snapshot)
			if err != nil || same != tc.same {
				t.Fatalf("same=%v want=%v err=%v", same, tc.same, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sameSRunIdentityMembers(ctx, old, old); err == nil {
		t.Fatal("cancelled poll accepted")
	}
}

func TestSRunIdentityPollCommitOnlyChangesCurrentGateway(t *testing.T) {
	for _, tc := range []struct {
		name              string
		previous, current bool
		commits           int
	}{
		{"unchanged_no_history_growth", true, true, 0},
		{"first_inventory", false, true, 1},
		{"configuration_changed_while_reading", false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			reader := &snapshotReader{}
			s := &Server{operations: &operationsState{db: db}, reader: reader}
			item := srun4KIntegration{ConnectorID: "one", Host: "192.0.2.190", Source: "srun4k:one", SensorID: "one", ReconcileIntervalHours: 6, EventChannelState: "waiting"}
			snapshot := store.IdentitySnapshot{IdentityScope: store.IdentityScope{Source: item.Source, SensorID: item.SensorID}, IntervalSeconds: 21600, Events: []normalized.Event{}}
			mock.ExpectExec(`UPDATE srun4k_integrations SET last_identity_poll_at`).WithArgs(item.ConnectorID, item.Host, item.Source, item.SensorID, 6).WillReturnResult(sqlmock.NewResult(0, 1))
			q := mock.ExpectQuery(`SELECT document FROM identity_full_snapshots`).WithArgs(item.Source, item.SensorID)
			if tc.previous {
				raw, _ := json.Marshal(snapshot)
				q.WillReturnRows(sqlmock.NewRows([]string{"document"}).AddRow(raw))
			} else {
				q.WillReturnError(sql.ErrNoRows)
			}
			if !tc.previous {
				mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM srun4k_integrations`).WithArgs(item.ConnectorID, item.Host, item.Source, item.SensorID, 6).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(tc.current))
			}
			if err := s.commitSRunIdentityPoll(context.Background(), item, snapshot); err != nil || reader.commits != tc.commits {
				t.Fatalf("commits=%d want=%d error=%v", reader.commits, tc.commits, err)
			}
			if item.EventChannelState != "waiting" {
				t.Fatal("poll certified accounting channel")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNormalizeSRunObservedAtClampsClockSkew(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 30, 0, 123456789, time.UTC)
	wantNow := now.Truncate(time.Microsecond)
	// 远端 4K Redis 时钟快于本机 5 秒：钳位到本机时间并保持微秒精度
	if got := normalizeSRunObservedAt(now.Add(5*time.Second), now); !got.Equal(wantNow) || got.Nanosecond()%1000 != 0 {
		t.Fatalf("future clock skew not clamped: got=%v want=%v", got, wantNow)
	}
	// 远端时钟落后 2 秒：保留远端时间并截断到微秒精度
	past := now.Add(-2 * time.Second)
	if got := normalizeSRunObservedAt(past, now); !got.Equal(past.Truncate(time.Microsecond)) || got.Nanosecond()%1000 != 0 {
		t.Fatalf("recent past time altered: got=%v want=%v", got, past.Truncate(time.Microsecond))
	}
	// 远端时钟异常落后超过 7 天：回落到本机时间
	if got := normalizeSRunObservedAt(now.Add(-8*24*time.Hour), now); !got.Equal(wantNow) {
		t.Fatalf("stale clock not clamped: got=%v want=%v", got, wantNow)
	}
}
