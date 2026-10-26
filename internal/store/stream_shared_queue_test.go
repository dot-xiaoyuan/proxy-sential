package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestPrepareStreamSharedJobsCoalescesKeysAndKeepsCoverage(t *testing.T) {
	now := time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)
	base := normalized.Event{SchemaVersion: "v1", Source: "handshake-sidecar", Type: "device", Timestamp: now.Format(time.RFC3339Nano),
		Observer: map[string]any{"sensor_id": "sensor", "capture_scope_id": "scope", "collector_instance_id": "collector"}, Subject: map[string]any{"campus_id": "campus", "ip": "10.0.0.2"}, Payload: map[string]any{"access_domain": "bond0"}}
	a := base
	a.EventID, a.SourceEventType = "one", "handshake"
	b := base
	b.EventID, b.SourceEventType = "two", "handshake"
	b.Timestamp = now.Add(time.Second).Format(time.RFC3339Nano)
	c := base
	c.EventID, c.SourceEventType = "coverage", "capture_coverage"
	c.Subject = map[string]any{"campus_id": "campus"}
	c.Payload = map[string]any{"access_domain": "bond0", "capture_coverage": map[string]any{"schema_version": "capture-coverage/v2", "covered_from": now.Add(-time.Second).Format(time.RFC3339Nano), "covered_to": now.Format(time.RFC3339Nano), "kernel_stats_known": true}}
	segment := streamlog.Segment{Epoch: "fresh", Source: "device-signals", SourcePath: "/signals/handshake.jsonl", Events: []normalized.Event{a, b, c}}
	prepared, err := prepareStreamSharedJobs(segment)
	if err != nil || prepared.Owner != "handshake-sidecar" || len(prepared.Handshakes) != 1 || len(prepared.Coverage) != 1 || len(prepared.Gateways) != 0 {
		t.Fatalf("jobs=%+v err=%v", prepared, err)
	}
	if !prepared.Handshakes[0].At.Equal(now.Add(time.Second)) {
		t.Fatalf("latest event lost: %+v", prepared.Handshakes[0])
	}
}

func TestStreamSharedSegmentReceiptPreventsDuplicateBusinessWake(t *testing.T) {
	at := time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)
	segment := streamlog.Segment{Epoch: "fresh", Source: "device-signals", SourcePath: "/signals/handshake.jsonl", ArchiveMonth: "202610", AcceptedAt: at, Events: []normalized.Event{
		{SchemaVersion: "v1", EventID: "packet-context", Source: "packet-sidecar", SourceEventType: "ttl", Type: "device", Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor", "capture_scope_id": "scope", "collector_instance_id": "collector"}, Subject: map[string]any{"campus_id": "campus", "ip": "10.0.0.2"}, Payload: map[string]any{"access_domain": "bond0"}},
		{SchemaVersion: "v1", EventID: "one", Source: "handshake-sidecar", SourceEventType: "handshake", Type: "device", Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor", "capture_scope_id": "scope", "collector_instance_id": "collector"}, Subject: map[string]any{"campus_id": "campus", "ip": "10.0.0.2"}, Payload: map[string]any{"access_domain": "bond0"}},
	}}
	p, err := prepareStreamSharedJobs(segment)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	queue := StreamSharedJobQueue{DB: db}
	for _, mode := range []string{"first", "repeat", "conflict"} {
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT sensor_id,scope_id,cancel_id FROM stream_shared_source_cutovers").WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "scope_id", "cancel_id"}).AddRow("sensor", "scope", "cancel"))
		insert := mock.ExpectExec("INSERT INTO stream_shared_segment_receipts")
		if mode == "first" {
			insert.WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec("INSERT INTO shared_observation_jobs").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
		} else {
			insert.WillReturnResult(sqlmock.NewResult(0, 0))
			prior := p.Hash
			if mode == "conflict" {
				prior = "another-content"
			}
			mock.ExpectQuery("SELECT segment_sha256 FROM stream_shared_segment_receipts").WillReturnRows(sqlmock.NewRows([]string{"segment_sha256"}).AddRow(prior))
			if mode == "repeat" {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}
		}
		err := queue.MarkStreamSharedJobs(context.Background(), "fixed-segment", segment)
		if (mode == "conflict") != errors.Is(err, streamlog.ErrContentConflict) {
			t.Fatalf("mode=%s err=%v", mode, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareStreamSharedJobsRejectsMixedOwners(t *testing.T) {
	events := []normalized.Event{
		{Source: "handshake-sidecar", SourceEventType: "handshake", Type: "device"},
		{Source: "packet-sidecar", SourceEventType: "capture_coverage", Type: "device"},
	}
	if _, err := prepareStreamSharedJobs(streamlog.Segment{Source: "device-signals", Events: events}); err == nil {
		t.Fatal("mixed source owners were accepted")
	}
}

func TestPrepareStreamSharedJobsAllowsHandshakeFilePacketPassiveContext(t *testing.T) {
	at := time.Date(2026, 10, 25, 15, 40, 0, 0, time.UTC)
	base := normalized.Event{Type: "device", Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor", "capture_scope_id": "scope", "collector_instance_id": "collector"}, Subject: map[string]any{"campus_id": "campus", "ip": "10.0.0.2"}, Payload: map[string]any{"access_domain": "bond0"}}
	ttl := base
	ttl.Source, ttl.SourceEventType, ttl.EventID = "packet-sidecar", "ttl", "ttl-one"
	ndp := base
	ndp.Source, ndp.SourceEventType, ndp.EventID = "packet-sidecar", "ndp", "ndp-one"
	ssdp := base
	ssdp.Source, ssdp.SourceEventType, ssdp.EventID = "packet-sidecar", "ssdp", "ssdp-one"
	handshake := base
	handshake.Source, handshake.SourceEventType, handshake.EventID = "handshake-sidecar", "handshake", "handshake-one"
	segment := streamlog.Segment{Epoch: "fresh", Source: "device-signals", SourcePath: "/signals/handshake.jsonl", Events: []normalized.Event{ttl, ndp, ssdp, handshake}}
	got, err := prepareStreamSharedJobs(segment)
	if err != nil || got.Owner != "handshake-sidecar" || len(got.Handshakes) != 1 || len(got.Gateways) != 0 {
		t.Fatalf("handshake file packet context must not change shared owner: %+v %v", got, err)
	}
}

func TestPrepareStreamSharedJobsKeepsPacketOwnerWithPassiveContext(t *testing.T) {
	at := time.Date(2026, 10, 25, 15, 40, 0, 0, time.UTC)
	base := normalized.Event{Type: "device", Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor", "capture_scope_id": "scope", "collector_instance_id": "collector"}, Subject: map[string]any{"campus_id": "campus"}, Payload: map[string]any{"access_domain": "bond0"}}
	ndp := base
	ndp.Source, ndp.SourceEventType, ndp.EventID = "packet-sidecar", "ndp", "ndp-one"
	association := base
	association.Source, association.SourceEventType, association.EventID = "packet-sidecar", "ieee1905_client_association", "association-one"
	association.Subject = map[string]any{"campus_id": "campus", "mac": "02:00:00:00:00:01"}
	segment := streamlog.Segment{Epoch: "fresh", Source: "device-signals", SourcePath: "/signals/ttl.jsonl", Events: []normalized.Event{ndp, association}}
	got, err := prepareStreamSharedJobs(segment)
	if err != nil || got.Owner != "packet-sidecar" || len(got.Gateways) != 1 {
		t.Fatalf("packet owner or gateway wake lost: %+v %v", got, err)
	}
}
