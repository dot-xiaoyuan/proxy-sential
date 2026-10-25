package main

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/streamlog"
)

func TestZeekStreamRunRequiresMatchingActiveCutover(t *testing.T) {
	cursor := streamlog.SourceCursor{Epoch: "fresh-dhcp", Source: "zeek-dhcp", Path: "/zeek/dhcp.log", FileID: "file-1", DiscardedBeforeOffset: 120, Offset: 120, ParserVersion: "zeek-v1"}
	for _, tc := range []struct {
		name, sensor, file, parser, manifest string
		start                                int64
		wantErr                              bool
	}{
		{name: "matching", sensor: "sensor-a", file: "file-1", parser: "zeek-v1", manifest: "abc", start: 120},
		{name: "wrong sensor", sensor: "sensor-b", file: "file-1", parser: "zeek-v1", manifest: "abc", start: 120, wantErr: true},
		{name: "wrong offset", sensor: "sensor-a", file: "file-1", parser: "zeek-v1", manifest: "abc", start: 0, wantErr: true},
		{name: "missing manifest", sensor: "sensor-a", file: "file-1", parser: "zeek-v1", start: 120, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery(`FROM stream_source_cutovers`).WithArgs(cursor.Epoch, cursor.Source, cursor.Path).
				WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "start_offset", "parser_version", "cancel_manifest_sha256", "capture_scope_sha256"}).AddRow(tc.sensor, tc.file, tc.start, tc.parser, tc.manifest, strings.Repeat("a", 64)))
			err = verifyIngestStreamCutover(context.Background(), db, cursor, "sensor-a", strings.Repeat("a", 64))
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected cutover result: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestControlledSignalStreamNeedsItsOwnAuditedCutover(t *testing.T) {
	cursor := streamlog.SourceCursor{Epoch: "fresh-ttl", Source: "device-signals", Path: "/signals/ttl.jsonl", FileID: "file-2", DiscardedBeforeOffset: 200, Offset: 200, ParserVersion: "device-v1"}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`FROM stream_source_cutovers`).WithArgs(cursor.Epoch, cursor.Source, cursor.Path).
		WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "start_offset", "parser_version", "cancel_manifest_sha256", "capture_scope_sha256"}).AddRow("sensor-a", "file-2", int64(200), "device-v1", "manifest", strings.Repeat("b", 64)))
	if err := verifyIngestStreamCutover(context.Background(), db, cursor, "sensor-a", strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifiedDHCPBindingHasItsOwnParserVersion(t *testing.T) {
	if got := streamParserForSource("zeek-dhcp-binding"); got != "zeek-dhcp-binding-v2" {
		t.Fatalf("verified DHCP binding parser version: %q", got)
	}
	if streamParserForSource("zeek-dhcp-binding") == streamParserForSource("zeek-dhcp") {
		t.Fatal("aggregate and verified DHCP bindings share a parser version")
	}
}

func TestVerifiedBindingRestartAfterRotationKeepsOriginalCutover(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation uint64
		last       string
		wantErr    bool
	}{
		{name: "verified second generation", generation: 2, last: "committed-rotation"},
		{name: "first generation cannot rewind below cutoff", generation: 1, last: "committed-rotation", wantErr: true},
		{name: "uncommitted replacement cannot rewind", generation: 2, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cursor := streamlog.SourceCursor{Epoch: "fresh-binding", Source: "zeek-dhcp-binding", Path: "/zeek/current/device_dhcp_binding.log", FileID: "new-file", DiscardedBeforeOffset: 742359, Offset: 2475, ParserVersion: "zeek-dhcp-binding-v2", KeyScheme: "generation-v2", Generation: tc.generation, LastSegmentID: tc.last}
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery(`FROM stream_source_cutovers`).WithArgs(cursor.Epoch, cursor.Source, cursor.Path).
				WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "start_offset", "parser_version", "cancel_manifest_sha256", "capture_scope_sha256"}).AddRow("sensor-a", "old-file", int64(742359), "zeek-dhcp-binding-v2", "manifest", strings.Repeat("c", 64)))
			err = verifyIngestStreamCutover(context.Background(), db, cursor, "sensor-a", strings.Repeat("c", 64))
			if (err != nil) != tc.wantErr {
				t.Fatalf("rotation restart validation: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
