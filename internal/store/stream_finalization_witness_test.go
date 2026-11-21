package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type witnessProjector struct {
	calls      []string
	witnessErr error
}

func (*witnessProjector) ProjectStreamSegment(context.Context, string, streamlog.Segment) error {
	return nil
}

func (*witnessProjector) ReconcileStreamProjection(context.Context, string, streamlog.Segment) error {
	return nil
}

func (p *witnessProjector) MarkStreamArchiveConfirmed(context.Context, string, streamlog.Segment) error {
	p.calls = append(p.calls, "archive")
	return nil
}

func (p *witnessProjector) MarkStreamSegmentFinalized(context.Context, string, streamlog.Segment) error {
	p.calls = append(p.calls, "witness")
	return p.witnessErr
}

type witnessSharedQueue struct{ calls *[]string }

func TestDHCPMessageStreamFinalizationProjectsAuthoritativeLeases(t *testing.T) {
	s := activityV3PrivatePostgres(t)
	schema, err := os.ReadFile("../../migrations/postgres/029_device_address_leases.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pg.db.Exec(string(schema)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const mac, ip, campus, sensor = "02:00:00:00:00:12", "192.0.2.12", "campus-a", "sensor-a"
	at := time.Date(2026, 11, 21, 7, 0, 0, 0, time.UTC)
	var input, output bytes.Buffer
	for offset, message := range []string{"REQUEST", "ACK", "RELEASE"} {
		observed := at.Add(time.Duration(offset) * time.Second).Format(time.RFC3339)
		if err := json.NewEncoder(&input).Encode(map[string]any{
			"ts": observed, "msg_types": message, "mac": mac, "requested_addr": ip,
			"assigned_addr": ip, "client_addr": ip, "lease_time": 600, "lease_observed_at": observed,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = zeek.Convert(&input, &output, zeek.Options{LogKind: "dhcp-message", SensorID: sensor}); err != nil {
		t.Fatal(err)
	}
	reader := json.NewDecoder(&output)
	segment := testStreamSegment()
	segment.Source, segment.SourcePath = "zeek-dhcp-binding", "/logs/current/device_dhcp_message.log"
	segment.Events = nil
	for reader.More() {
		var event normalized.Event
		if err := reader.Decode(&event); err != nil {
			t.Fatal(err)
		}
		event.Subject["campus_id"] = campus
		segment.Events = append(segment.Events, event)
	}
	if len(segment.Events) != 3 {
		t.Fatalf("DHCP adapter emitted %d events, want three", len(segment.Events))
	}
	writer := StreamLaneWriter{Projector: &witnessProjector{}, DeviceLeaseDB: s.pg.db}
	for range 2 {
		if err = writer.FinalizeSegment(ctx, "dhcp-segment", segment); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = s.pg.db.QueryRowContext(ctx, "SELECT count(*) FROM device_address_leases").Scan(&count); err != nil || count != 2 {
		t.Fatalf("want one ACK and one release after retry, got %d: %v", count, err)
	}
	for offset, want := range []string{"", ip, ""} {
		got, err := s.ieee1905GatewayIPAt(ctx, sensor, campus, mac, at.Add(time.Duration(offset)*time.Second))
		if err != nil || got != want {
			t.Fatalf("at message %d got IP %q, want %q: %v", offset, got, want, err)
		}
	}
}

func (q witnessSharedQueue) MarkStreamSharedJobs(context.Context, string, streamlog.Segment) error {
	*q.calls = append(*q.calls, "shared")
	return nil
}

type archiveOnlyProjector struct{}

func (archiveOnlyProjector) ProjectStreamSegment(context.Context, string, streamlog.Segment) error {
	return nil
}

func (archiveOnlyProjector) ReconcileStreamProjection(context.Context, string, streamlog.Segment) error {
	return nil
}

func (archiveOnlyProjector) MarkStreamArchiveConfirmed(context.Context, string, streamlog.Segment) error {
	return nil
}

func TestProjectedSegmentRequiresFinalizationWitness(t *testing.T) {
	segment := testStreamSegment()
	if err := (StreamLaneWriter{Projector: archiveOnlyProjector{}}).FinalizeSegment(context.Background(), "segment-a", segment); !errors.Is(err, ErrStreamProjectorUnavailable) {
		t.Fatalf("projected segment released without witness: %v", err)
	}
	segment.NeedsProjection = false
	if err := (StreamLaneWriter{Projector: archiveOnlyProjector{}}).FinalizeSegment(context.Background(), "segment-a", segment); err != nil {
		t.Fatalf("unprojected segment was blocked by witness: %v", err)
	}
}

func TestStreamFinalizationWitnessFollowsOtherReceipts(t *testing.T) {
	projector := &witnessProjector{}
	segment := testStreamSegment()
	segment.Events[0].Source = "handshake-sidecar"
	segment.Events[0].SourceEventType = "handshake"
	writer := StreamLaneWriter{Projector: projector, SharedQueue: witnessSharedQueue{calls: &projector.calls}}
	if err := writer.FinalizeSegment(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projector.calls, []string{"archive", "shared", "witness"}) {
		t.Fatalf("witness preceded a required receipt: %v", projector.calls)
	}
	projector.calls = nil
	segment.SplitRiskFeatures, segment.RiskFeaturesRequired = true, true
	if err := writer.FinalizeSegment(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projector.calls, []string{"archive", "shared", "witness"}) {
		t.Fatalf("split feature path skipped witness: %v", projector.calls)
	}
}

func TestStreamWitnessFailureKeepsJournalForRetry(t *testing.T) {
	segment := testStreamSegment()
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.PreviousFileID, Offset: segment.PreviousOffset, ParserVersion: segment.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(segment.Source, segment.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	for _, lane := range []streamlog.Lane{streamlog.Archive, streamlog.Search, streamlog.Projection} {
		if err := j.Ack(id, lane); err != nil {
			t.Fatal(err)
		}
	}
	projector := &witnessProjector{witnessErr: errors.New("unknown database outcome")}
	processor := streamlog.Processor{Journal: j, Writer: StreamLaneWriter{Projector: projector}}
	if err := processor.FinalizeAfterLanes(context.Background(), id); err == nil {
		t.Fatal("ambiguous witness released its journal segment")
	}
	if _, err := j.Load(id); err != nil {
		t.Fatalf("failed witness lost segment: %v", err)
	}
	projector.witnessErr = nil
	if err := processor.FinalizeAfterLanes(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Load(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful retry left segment: %v", err)
	}
	if !reflect.DeepEqual(projector.calls, []string{"archive", "witness", "archive", "witness"}) {
		t.Fatalf("finalization retry order changed: %v", projector.calls)
	}
}
