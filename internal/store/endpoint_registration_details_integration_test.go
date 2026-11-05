package store

import (
	"context"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestLocalRegistrationPreservesObservedIdentityAndSeparateAddress(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	id := "mac:02:00:00:20:40:01"
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	t.Cleanup(func() {
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM discovery_identity_links WHERE observation_id='local-registration-arp'`)
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM discovery_observations WHERE id='local-registration-arp'`)
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, id)
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, id)
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE target=$1 AND action='endpoints.registration.update'`, "endpoint:"+id)
	})
	update := EndpointRegistrationUpdate{EndpointID: id, RegistrationStatus: "registered", OwnerName: "管理员", OwnershipClass: "school_asset", AssetTag: "204-PRINT-1", MergeStatus: "active", RegistrationUpdatedBy: "test-operator", RegistrationUpdatedAt: stamp, RegistrationDetails: &EndpointRegistrationDetails{Name: "教室打印机", DeviceType: "printer", Model: "M252n", RegisteredIP: "10.152.41.41", Location: "教学楼"}}
	endpoint, err := pg.UpdateEndpointRegistration(ctx, update)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.PrimaryMAC != "02:00:00:20:40:01" || endpoint.LastSeen != "" {
		t.Fatalf("registration invented an observed device/address: %+v", endpoint)
	}
	details, ok := endpoint.Attributes["manual_registration"].(map[string]any)
	if !ok || details["name"] != "教室打印机" || details["registered_ip"] != "10.152.41.41" || details["source"] != "local" {
		t.Fatalf("manual registration was not persisted: %+v", endpoint.Attributes)
	}
	profile, found, err := pg.GetEndpointIdentity(ctx, id, Query{Limit: 20})
	if err != nil || !found {
		t.Fatalf("registration-only endpoint is not readable: found=%v err=%v", found, err)
	}
	if profile.Endpoint.PrimaryMAC != "02:00:00:20:40:01" || profile.Endpoint.Attributes["manual_registration"] == nil {
		t.Fatalf("registration-only detail lost manual facts: %+v", profile.Endpoint)
	}
	var addressCount int
	if err := pg.db.QueryRowContext(ctx, `SELECT count(*) FROM identity_ip_mac_history WHERE endpoint_id=$1`, id).Scan(&addressCount); err != nil || addressCount != 0 {
		t.Fatalf("registered IP became observed address: count=%d err=%v", addressCount, err)
	}
	update.RegistrationDetails = nil
	update.RegistrationUpdatedAt = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	endpoint, err = pg.UpdateEndpointRegistration(ctx, update)
	if err != nil {
		t.Fatal(err)
	}
	details, ok = endpoint.Attributes["manual_registration"].(map[string]any)
	if !ok || details["registered_ip"] != "10.152.41.41" {
		t.Fatalf("legacy update cleared manual registration: %+v", endpoint.Attributes)
	}
	arp := passiveTestEvent("arp", "10.152.41.42", "02:00:00:20:40:01", map[string]any{})
	arp.EventID = "local-registration-arp"
	arp.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/8")
	worker := &DBStore{pg: pg}
	if _, err := worker.processPassiveDiscoveryBatch(ctx, []normalized.Event{arp}, scope); err != nil {
		t.Fatal(err)
	}
	endpoint, found, err = pg.getEndpointEntity(ctx, id)
	if err != nil || !found || endpoint.LastSeen == "" || endpoint.IdentityConfidence < 0.55 || endpoint.Attributes["manual_registration"] == nil {
		t.Fatalf("ARP did not link registration-only identity while preserving facts: found=%v endpoint=%+v err=%v", found, endpoint, err)
	}
}
