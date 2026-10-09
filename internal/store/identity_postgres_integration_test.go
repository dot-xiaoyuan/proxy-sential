package store

import (
	"context"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestPostgresIdentitySessionPersistsUniversityDimensionsAndEndTime(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	postgres, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer postgres.Close()

	const sessionID = "integration-university-session"
	const endpointID = "mac:02:00:00:00:00:31"
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM identity_access_history WHERE event_id IN ('integration-identity-start','integration-identity-stop','integration-identity-reused')`)
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM identity_ip_mac_history WHERE event_id IN ('integration-identity-start','integration-identity-stop','integration-identity-reused')`)
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM account_sessions WHERE session_id IN ($1,'integration-university-session-b')`, sessionID)
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM endpoint_entities WHERE endpoint_id IN ($1,'mac:02:00:00:00:00:32')`, endpointID)

	events := []normalized.Event{
		universityIdentityEvent("integration-identity-start", sessionID, "start", "2026-08-31T10:00:00Z"),
		universityIdentityEvent("integration-identity-stop", sessionID, "stop", "2026-08-31T11:00:00Z"),
	}
	if err := postgres.WriteIdentityEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	// IP search must work before paging and must not duplicate a device for repeated observations.
	for _, q := range []string{"192.0.2.31"} {
		page, err := postgres.ListEndpointDevices(ctx, Query{Q: q, Limit: 1})
		if err != nil || page.Page.Total != 1 || len(page.Items) != 1 || page.Items[0].EndpointID != endpointID {
			t.Fatalf("IP search %q: page=%+v err=%v", q, page, err)
		}
	}
	// A complete IPv4 search denotes that address, not a textual prefix of .31.
	if page, err := postgres.ListEndpointDevices(ctx, Query{Q: "192.0.2.3", Limit: 1}); err != nil || page.Page.Total != 0 {
		t.Fatalf("complete IP broadened into a prefix: total=%d err=%v", page.Page.Total, err)
	}
	updatedEndpoint, err := postgres.UpdateEndpointRegistration(ctx, EndpointRegistrationUpdate{EndpointID: endpointID, RegistrationStatus: "registered", OwnershipClass: "school_asset", AssetTag: "ASSET-INTEGRATION-31", MergeStatus: "active", RegistrationUpdatedBy: "integration-admin", RegistrationUpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil || updatedEndpoint.OwnershipClass != "school_asset" {
		t.Fatalf("endpoint ownership class was not persisted: value=%+v err=%v", updatedEndpoint, err)
	}
	var vendorConfidence, brandConfidence, modelConfidence, deviceTypeConfidence, osConfidence float64
	if err := postgres.db.QueryRowContext(ctx, `SELECT vendor_confidence,brand_confidence,model_confidence,device_type_confidence,os_family_confidence FROM endpoint_device_profiles WHERE endpoint_id=$1`, endpointID).Scan(&vendorConfidence, &brandConfidence, &modelConfidence, &deviceTypeConfidence, &osConfidence); err != nil {
		t.Fatal(err)
	}
	if vendorConfidence < 0 || brandConfidence < 0 || modelConfidence < 0 || deviceTypeConfidence < 0 || osConfidence < 0 {
		t.Fatalf("field confidence values must be persisted independently: %f %f %f %f %f", vendorConfidence, brandConfidence, modelConfidence, deviceTypeConfidence, osConfidence)
	}
	var started, ended time.Time
	var personType, department, campusID, buildingID, zoneID, ssid, vlan, ap, nasIP, status string
	err = postgres.db.QueryRowContext(ctx, `SELECT started_at,ended_at,person_type,department,campus_id,building_id,network_zone_id,ssid,vlan,ap,host(nas_ip),session_status FROM account_sessions WHERE session_id=$1`, sessionID).Scan(&started, &ended, &personType, &department, &campusID, &buildingID, &zoneID, &ssid, &vlan, &ap, &nasIP, &status)
	if err != nil {
		t.Fatal(err)
	}
	if started.UTC().Format(time.RFC3339) != "2026-08-31T10:00:00Z" || ended.UTC().Format(time.RFC3339) != "2026-08-31T11:00:00Z" {
		t.Fatalf("unexpected persisted session window: %s - %s", started, ended)
	}
	if personType != "student" || department != "计算机学院" || campusID != "campus-east" || buildingID != "dorm-3" || zoneID != "student-wireless" || ssid != "Campus-WiFi" || vlan != "310" || ap != "AP-D3-01" || nasIP != "10.0.0.10" || status != "stop" {
		t.Fatalf("university dimensions were not persisted: %q %q %q %q %q %q %q %q %q %q", personType, department, campusID, buildingID, zoneID, ssid, vlan, ap, nasIP, status)
	}
	attribution, found, err := postgres.ResolveIdentityAt(ctx, "192.0.2.31", "2026-08-31T10:30:00Z")
	if err != nil || !found || attribution.AccountID != "student-31" || attribution.SessionID != sessionID || attribution.CampusID != "campus-east" {
		t.Fatalf("risk-time attribution failed: found=%v value=%+v err=%v", found, attribution, err)
	}
	reused := universityIdentityEvent("integration-identity-reused", "integration-university-session-b", "start", "2026-08-31T11:01:00Z")
	reused.Subject["account_id"] = "student-32"
	reused.Subject["endpoint_id"] = "mac:02:00:00:00:00:32"
	reused.Subject["mac"] = "02:00:00:00:00:32"
	reused.Payload["campus_id"] = "campus-west"
	if err := postgres.WriteIdentityEvents(ctx, []normalized.Event{reused}); err != nil {
		t.Fatal(err)
	}
	attribution, found, err = postgres.ResolveIdentityAt(ctx, "192.0.2.31", "2026-08-31T11:02:00Z")
	if err != nil || !found || attribution.AccountID != "student-32" || attribution.EndpointID != "mac:02:00:00:00:00:32" || attribution.Conflict {
		t.Fatalf("reused IP crossed authentication sessions: found=%v value=%+v err=%v", found, attribution, err)
	}
	page, err := postgres.ListEndpointDevices(ctx, Query{CampusID: "campus-east", Department: "计算机学院", PersonType: "student", SSID: "Campus-WiFi", VLAN: "310", AP: "AP-D3-01", NASIP: "10.0.0.10", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if page.Page.Total != 0 {
		t.Fatalf("ended session must not be returned as currently attached endpoint, got %+v", page)
	}
	const backfillVersion = "integration-offline-library-v1"
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM device_profile_backfill_jobs WHERE version=$1`, backfillVersion)
	_, err = postgres.db.ExecContext(ctx, `INSERT INTO device_profile_backfill_jobs(version,status,processed,last_error,started_at,updated_at) VALUES($1,'failed',1,'simulated interruption',now(),now())`, backfillVersion)
	if err != nil {
		t.Fatal(err)
	}
	progressCalls := 0
	backfill, err := postgres.RebuildDeviceProfilesVersion(ctx, backfillVersion, 1, func(item DeviceProfileBackfillProgress) {
		progressCalls++
		if item.Version != backfillVersion {
			t.Errorf("unexpected progress version: %+v", item)
		}
	})
	if err != nil || backfill.Status != "completed" || backfill.Processed <= 1 || progressCalls < 2 {
		t.Fatalf("failed backfill did not resume to completion: progress=%+v callbacks=%d err=%v", backfill, progressCalls, err)
	}
	var persistedStatus string
	var persistedProcessed int
	if err := postgres.db.QueryRowContext(ctx, `SELECT status,processed FROM device_profile_backfill_jobs WHERE version=$1`, backfillVersion).Scan(&persistedStatus, &persistedProcessed); err != nil || persistedStatus != "completed" || persistedProcessed != backfill.Processed {
		t.Fatalf("backfill progress was not persisted: status=%s processed=%d err=%v", persistedStatus, persistedProcessed, err)
	}
}

func universityIdentityEvent(eventID, sessionID, status, timestamp string) normalized.Event {
	return normalized.Event{
		SchemaVersion: "v1", EventID: eventID, Source: "radius", SourceEventType: "identity", Type: "identity", Timestamp: timestamp,
		Observer:   map[string]any{"sensor_id": "integration"},
		Subject:    map[string]any{"ip": "192.0.2.31", "mac": "02:00:00:00:00:31", "endpoint_id": "mac:02:00:00:00:00:31", "account_id": "student-31", "access_id": "AP-D3-01", "entity_role": "endpoint", "identity_confidence": 0.98},
		Flow:       map[string]any{"src_ip": "192.0.2.31", "dst_ip": "0.0.0.0", "proto": "other", "direction": "unknown"},
		Payload:    map[string]any{"origin": "radius", "session_id": sessionID, "session_status": status, "person_type": "student", "department": "计算机学院", "campus_id": "campus-east", "building_id": "dorm-3", "network_zone_id": "student-wireless", "ssid": "Campus-WiFi", "vlan": "310", "ap": "AP-D3-01", "nas_ip": "10.0.0.10"},
		Confidence: 0.98,
	}
}
