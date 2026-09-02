package store

import (
	"context"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

func TestPostgresDomainEvidenceIsIdempotentAndSessionScoped(t *testing.T) {
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
	endpointID := "mac:02:00:00:00:09:12"
	sessionID := "domain-integration-session"
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM endpoint_domain_evidence_events WHERE endpoint_id=$1`, endpointID)
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM endpoint_domain_evidence WHERE endpoint_id=$1`, endpointID)
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM account_sessions WHERE session_id=$1`, sessionID)
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, endpointID)
	identity := normalized.Event{SchemaVersion: "v1", EventID: "domain-identity-start", Source: "radius", Type: "identity", Timestamp: "2026-09-02T10:00:00Z", Subject: map[string]any{"ip": "192.0.2.212", "mac": "02:00:00:00:09:12", "endpoint_id": endpointID, "account_id": "student-domain", "entity_role": "endpoint"}, Flow: map[string]any{}, Payload: map[string]any{"session_id": sessionID, "session_status": "start"}, Confidence: 0.99}
	if err := postgres.WriteIdentityEvents(ctx, []normalized.Event{identity}); err != nil {
		t.Fatal(err)
	}
	library, err := fingerprint.LoadWithDomainData("domain-integration-v1", []byte("Registry,Assignment,Organization Name\nMA-L,000C29,VMware\n"), []byte("[]"), []byte("[]"), []byte("{}"), []byte(`[{"domain":"push.apple.test","match_type":"subdomain","ecosystem":"Apple","category":"push","confidence":0.55,"source":"NextDNS"}]`))
	if err != nil {
		t.Fatal(err)
	}
	event := normalized.Event{SchemaVersion: "v1", EventID: "domain-evidence-1", Source: "suricata", Type: "tls", Timestamp: "2026-09-02T10:05:00Z", Subject: map[string]any{"ip": "192.0.2.212"}, Flow: map[string]any{}, Payload: map[string]any{"sni": "push.apple.test"}, Confidence: 1}
	for range 2 {
		if _, err := postgres.ProcessDomainEvents(ctx, []normalized.Event{event}, library); err != nil {
			t.Fatal(err)
		}
	}
	items, err := postgres.ListEndpointDomainEvidence(ctx, endpointID, 20)
	if err != nil || len(items) != 1 || items[0].Count != 1 || items[0].AttributionMethod != "active_auth_session" {
		t.Fatalf("idempotent evidence failed: %+v err=%v", items, err)
	}
	ended := identity
	ended.EventID = "domain-identity-stop"
	ended.Timestamp = "2026-09-02T10:10:00Z"
	ended.Payload = map[string]any{"session_id": sessionID, "session_status": "stop"}
	if err := postgres.WriteIdentityEvents(ctx, []normalized.Event{ended}); err != nil {
		t.Fatal(err)
	}
	event.EventID = "domain-evidence-after-session"
	event.Timestamp = "2026-09-02T10:11:00Z"
	result, err := postgres.ProcessDomainEvents(ctx, []normalized.Event{event}, library)
	if err != nil || result.Attributed != 0 {
		t.Fatalf("ended session must not receive evidence: %+v err=%v", result, err)
	}
}
