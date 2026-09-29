package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/store"
)

func TestFingerprintStatusPersistsToPostgresVersionLedger(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	operations, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer operations.db.Close()
	version := "integration-fingerprint-" + shortToken(6)
	status := fingerprint.Status{Version: version, Status: "ready", Source: "offline-bundle", Checksum: "integration-checksum", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), RuleCount: 9, ApplicationRuleCount: 4, BackfillStatus: "completed", BackfillProcessed: 49}
	server := &Server{operations: operations}
	if err := server.persistFingerprintStatus(ctx, status); err != nil {
		t.Fatal(err)
	}
	defer operations.db.ExecContext(context.Background(), `DELETE FROM device_fingerprint_versions WHERE version=$1`, version)
	var source, state string
	var details []byte
	if err := operations.db.QueryRowContext(ctx, `SELECT source,status,details FROM device_fingerprint_versions WHERE version=$1`, version).Scan(&source, &state, &details); err != nil {
		t.Fatal(err)
	}
	var persisted fingerprint.Status
	if err := json.Unmarshal(details, &persisted); err != nil {
		t.Fatal(err)
	}
	if source != status.Source || state != status.Status || persisted.RuleCount != 9 || persisted.BackfillStatus != "completed" {
		t.Fatalf("unexpected fingerprint ledger row: source=%s status=%s details=%+v", source, state, persisted)
	}
}
