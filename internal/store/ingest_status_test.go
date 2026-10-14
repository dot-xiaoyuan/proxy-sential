package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

var ingestStatusRunColumns = []string{"run_id", "sensor_id", "started_at", "finished_at", "previous_offset", "new_offset", "truncated", "normalized_read", "normalized_emitted", "normalized_skipped", "normalized_malformed", "evidence_count", "risk_count", "risk_list_count", "summary"}

var sensorMetadataColumns = []string{"sensor_id", "display_name", "collector_kind", "collector_version", "interface_name"}

// One ingest service commits a separate run per configured input, so the
// collector cards must summarize the newest run of every source instead of
// alternating between the busiest and the quietest one. An idle heartbeat run
// must never report zero while another source is producing events.
func TestIngestStatusSummarizesLatestRunPerSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	rows := sqlmock.NewRows(ingestStatusRunColumns).
		AddRow("heartbeat-run", "ncu-184", now, now, 0, 128, false, 0, 0, 0, 0, 0, 0, 0, []byte(`{"normalized":{"by_type":{}},"raw_ref":{"source":"/data/zeek/dhcp.log","offset":128}}`)).
		AddRow("device-batch", "ncu-184", now.Add(-1*time.Second), now.Add(-1*time.Second), 0, 4096, false, 6782, 6782, 0, 0, 0, 0, 0, []byte(`{"normalized":{"by_type":{"device":6782}},"raw_ref":{"source":"/data/device-signals/ttl.jsonl","start_offset":0,"end_offset":4096}}`)).
		AddRow("dhcp-batch", "ncu-184", now.Add(-2*time.Second), now.Add(-2*time.Second), 0, 64, false, 81, 78, 3, 0, 0, 0, 0, []byte(`{"normalized":{"by_type":{"device":78}},"raw_ref":{"source":"/data/zeek/dhcp.log","start_offset":0,"end_offset":64}}`)).
		AddRow("older-device-batch", "ncu-184", now.Add(-3*time.Second), now.Add(-3*time.Second), 0, 4096, false, 6700, 6700, 0, 0, 0, 0, 0, []byte(`{"normalized":{"by_type":{"device":6700}},"raw_ref":{"source":"/data/device-signals/ttl.jsonl","start_offset":0,"end_offset":4096}}`))
	mock.ExpectQuery(`FROM collector_runs WHERE sensor_id=\$1`).WithArgs("ncu-184", ingestStatusRunWindow).WillReturnRows(rows)
	mock.ExpectQuery(`FROM sensors WHERE sensor_id=\$1`).WithArgs("ncu-184").
		WillReturnRows(sqlmock.NewRows(sensorMetadataColumns))
	status, err := (&DBStore{pg: &PostgresStore{db: db, sensorID: "ncu-184"}}).IngestStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 6782 (device-signals) + 81 (zeek dhcp); the heartbeat contributes nothing
	// and the older device batch is superseded by the newer one.
	if status.LastCounters["read"] != 6863 || status.LastCounters["emitted"] != 6860 || status.LastCounters["skipped"] != 3 {
		t.Fatalf("status did not summarize the latest run per source: %+v", status.LastCounters)
	}
	if status.LastCounters["malformed"] != 0 || !status.Healthy {
		t.Fatalf("healthy pipeline reported unhealthy: %+v", status)
	}
	if status.LastEventTypeDist["device"] != 6860 {
		t.Fatalf("latest batch distribution changed: %+v", status.LastEventTypeDist)
	}
	if status.LatestRunID != "heartbeat-run" || status.LatestRunAt == "" {
		t.Fatalf("freshness fields must keep pointing at the newest run: %+v", status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A genuinely quiet sensor keeps reporting zero instead of borrowing a batch
// that is older than everything in the inspected window.
func TestIngestStatusKeepsHeartbeatWhenNoBatchProcessedInput(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	rows := sqlmock.NewRows(ingestStatusRunColumns).
		AddRow("heartbeat-run", "quiet", now, now, 0, 128, false, 0, 0, 0, 0, 0, 0, 0, []byte(`{"normalized":{"by_type":{}}}`))
	mock.ExpectQuery(`FROM collector_runs WHERE sensor_id=\$1`).WithArgs("quiet", ingestStatusRunWindow).WillReturnRows(rows)
	mock.ExpectQuery(`FROM sensors WHERE sensor_id=\$1`).WithArgs("quiet").
		WillReturnRows(sqlmock.NewRows(sensorMetadataColumns))
	status, err := (&DBStore{pg: &PostgresStore{db: db, sensorID: "quiet"}}).IngestStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.LatestRunID != "heartbeat-run" || status.LastCounters["read"] != 0 {
		t.Fatalf("quiet sensor state changed: %+v", status)
	}
}

// The control plane must report the collector the sensor registered, not the
// suricata/ens1f1 defaults its own process options used to carry.
func TestIngestStatusPrefersRegisteredSensorMetadata(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	rows := sqlmock.NewRows(ingestStatusRunColumns).
		AddRow("batch-run", "ncu-184", now, now, 0, 128, false, 6782, 6782, 0, 0, 0, 0, 0, []byte(`{"normalized":{"by_type":{}}}`))
	mock.ExpectQuery(`FROM collector_runs WHERE sensor_id=\$1`).WithArgs("ncu-184", ingestStatusRunWindow).WillReturnRows(rows)
	mock.ExpectQuery(`FROM sensors WHERE sensor_id=\$1`).WithArgs("ncu-184").
		WillReturnRows(sqlmock.NewRows(sensorMetadataColumns).AddRow("ncu-184", "ncu-184", "device-signal", "2026.10.15", "bond0"))
	status, err := (&DBStore{pg: &PostgresStore{db: db, sensorID: "ncu-184", collectorKind: "suricata", interfaceName: "ens1f1"}}).IngestStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Collector.Kind != "device-signal" || status.Collector.Interface != "bond0" || status.Collector.Version != "2026.10.15" {
		t.Fatalf("registered sensor metadata was ignored: %+v", status.Collector)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A sensor that never registered reports no collector metadata at all.
func TestSensorMetadataAbsentNeverInventsDefaults(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`FROM sensors WHERE sensor_id=\$1`).WithArgs("unknown").
		WillReturnRows(sqlmock.NewRows(sensorMetadataColumns))
	metadata, err := (&PostgresStore{db: db}).SensorMetadata(context.Background(), "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.CollectorKind != "" || metadata.InterfaceName != "" || metadata.CollectorVer != "" {
		t.Fatalf("absent sensor metadata invented defaults: %+v", metadata)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
