package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"testing"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

func TestSharedGatewaySnapshotReplayAndNegatives(t *testing.T) {
	now := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	scope := SharedObservationScope{"mirror", "campus", "domain", "192.0.2.4"}
	mac := "02:00:00:00:00:01"
	bss := "02:00:00:00:01:01"
	cfg := sharedaccess.Config{Version: "v1", FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, Source: "packet-sidecar"}}}
	coverage := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: now.Add(-20 * time.Second), To: now, KernelStatsKnown: true}
	raw, _ := json.Marshal(map[string]any{"capture_coverage": coverage, "bss_snapshots": []ieee1905AssociationSnapshot{{BSSID: bss, ClientMACs: []string{"02:00:00:00:00:02", "02:00:00:00:00:03"}}}})
	base := sharedAssociationEvent{sharedObservationEvent: sharedObservationEvent{Timestamp: now.Add(-10 * time.Second).Format(time.RFC3339Nano), EventID: "snapshot", Source: "packet-sidecar", Instance: "one", Payload: string(raw)}, MAC: mac, Kind: "ieee1905_client_snapshot"}
	for _, mode := range []string{"confirmed", "duplicate", "left", "empty_snapshot", "wrong_bss_left", "legacy", "loss", "expired_members", "conflicting_snapshot"} {
		t.Run(mode, func(t *testing.T) {
			rows := []sharedAssociationEvent{base}
			expected := mode == "confirmed" || mode == "duplicate" || mode == "wrong_bss_left"
			switch mode {
			case "duplicate":
				rows = append(rows, base)
			case "left", "wrong_bss_left":
				value := bss
				if mode == "wrong_bss_left" {
					value = "02:00:00:00:01:02"
				}
				payload, _ := json.Marshal(map[string]any{"capture_coverage": coverage, "bssid": value, "client_mac": "02:00:00:00:00:03", "association_state": "left"})
				negative := base
				negative.EventID = "leave"
				negative.Kind = "ieee1905_client_association"
				negative.Payload = string(payload)
				// Leave wins even with identical source timestamps and earlier lexical ID.
				rows = append(rows, negative)
			case "empty_snapshot", "conflicting_snapshot":
				payload, _ := json.Marshal(map[string]any{"capture_coverage": coverage, "bss_snapshots": []ieee1905AssociationSnapshot{{BSSID: bss, ClientMACs: []string{}}}})
				negative := base
				negative.EventID = "empty"
				negative.Payload = string(payload)
				if mode == "empty_snapshot" {
					negative.Timestamp = now.Add(-time.Second).Format(time.RFC3339Nano)
				}
				rows = append(rows, negative)
			case "legacy", "loss":
				cov := coverage
				if mode == "legacy" {
					cov.SchemaVersion = ""
				} else {
					cov.Dropped = 1
				}
				var payload map[string]any
				_ = json.Unmarshal([]byte(base.Payload), &payload)
				payload["capture_coverage"] = cov
				encoded, _ := json.Marshal(payload)
				rows[0].Payload = string(encoded)
			case "expired_members":
				rows[0].Timestamp = now.Add(-4 * time.Minute).Format(time.RFC3339Nano)
			}
			w := buildAssociationWindow(scope, mac, rows, now, cfg.Freshness())
			w.Conflicts = append(w.Conflicts, sharedaccess.VerifyCoverage(w, cfg, w.CoverageFacts)...)
			w.Complete = len(w.Conflicts) == 0
			w.CoverageVerified = w.Complete
			_, item, err := finalizeSharedObservation(w, cfg, now)
			if err != nil || item.Status == "confirmed" || (item.StrongAnchor == "ieee1905_association") != expected {
				t.Fatalf("assessment=%+v err=%v", item, err)
			}
			if expected && item.DeviceLowerBound != 2 {
				t.Fatalf("physical lower bound: %d", item.DeviceLowerBound)
			}
		})
	}
}

func TestSharedGatewayResolutionRetriesWithoutLosingWork(t *testing.T) {
	for _, mode := range []string{"resolved", "missing", "changed", "database_failure"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			now := time.Now().UTC()
			at := now.Add(-time.Second)
			mock.ExpectBegin()
			mock.ExpectQuery("SELECT job_id").WillReturnRows(sqlmock.NewRows([]string{"id", "sensor", "campus", "domain", "mac", "previous", "at", "received", "revision", "generation"}).AddRow("job", "sensor", "campus", "mirror", "02:00:00:00:00:01", "", at, at, 1, ""))
			query := mock.ExpectQuery("SELECT DISTINCT host")
			if mode == "database_failure" {
				query.WillReturnError(errors.New("storage unavailable"))
				mock.ExpectRollback()
				mock.ExpectExec("UPDATE shared_gateway_observation_jobs SET last_error").WillReturnResult(sqlmock.NewResult(0, 1))
			} else {
				initial := sqlmock.NewRows([]string{"ip"})
				if mode != "missing" {
					initial.AddRow("192.0.2.4")
				}
				query.WillReturnRows(initial)
				current := sqlmock.NewRows([]string{"ip"})
				if mode == "resolved" {
					current.AddRow("192.0.2.4")
				}
				if mode == "changed" {
					current.AddRow("192.0.2.5")
				}
				mock.ExpectQuery("SELECT DISTINCT host").WillReturnRows(current)
				if mode == "resolved" {
					mock.ExpectExec("INSERT INTO shared_observation_jobs").WillReturnResult(sqlmock.NewResult(0, 1))
				}
				mock.ExpectExec("UPDATE shared_gateway_observation_jobs SET completed_revision").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			}
			did, err := (&DBStore{pg: &PostgresStore{db: db}}).ResolveSharedGateway(context.Background(), sharedaccess.Config{}, now)
			if !did || (err != nil) != (mode == "database_failure") {
				t.Fatalf("did=%v err=%v", did, err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
