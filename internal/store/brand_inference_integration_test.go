package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

func brandReplay(t *testing.T) []normalized.Event {
	t.Helper()
	file, err := os.Open("../../examples/replay/device-brand-domain-inference.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	events := []normalized.Event{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var e normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func TestBrandInferenceNormalizedReplay(t *testing.T) {
	library := fingerprint.Default()
	now := time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC)
	evidence := []fingerprint.DomainEvidence{}
	for _, event := range brandReplay(t) {
		observation, ok := ExtractDomainObservation(event)
		if !ok {
			t.Fatal(event)
		}
		match, ok := library.MatchDomain(observation.Domain)
		if ok {
			evidence = append(evidence, fingerprint.DomainEvidence{Match: match, RuleVersion: library.Version(), FirstSeen: event.Timestamp, LastSeen: event.Timestamp, Count: 1, EventSource: event.Type, EventIDs: []string{event.EventID}})
		}
	}
	if len(evidence) != 4 {
		t.Fatalf("expected four observable device-service events, got %d", len(evidence))
	}
	result := fingerprint.InferBrand(evidence, library.Version(), now, "", 0)
	if result.Status != "inferred" || result.Brand != "Apple" {
		t.Fatalf("%+v", result)
	}
}

func TestPostgresBrandInferenceReplayWindowAndVersion(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	library := fingerprint.Default()
	id := fmt.Sprintf("brand-integration-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	var state []byte
	_ = pg.db.QueryRowContext(ctx, `SELECT to_jsonb(s) FROM domain_recognition_state s WHERE singleton`).Scan(&state)
	t.Cleanup(func() {
		_, _ = pg.db.ExecContext(context.Background(), `DELETE FROM endpoint_domain_evidence_events WHERE endpoint_id=$1`, id)
		_, _ = pg.db.ExecContext(context.Background(), `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, id)
		if len(state) == 0 {
			_, _ = pg.db.ExecContext(context.Background(), `DELETE FROM domain_recognition_state`)
		} else {
			_, _ = pg.db.ExecContext(context.Background(), `UPDATE domain_recognition_state SET active_version=$1::jsonb->>'active_version',pending_version=$1::jsonb->>'pending_version',last_error=$1::jsonb->>'last_error'`, state)
		}
	})
	_, err = pg.db.ExecContext(ctx, `INSERT INTO domain_recognition_state(singleton,active_version) VALUES(true,$1) ON CONFLICT(singleton) DO UPDATE SET active_version=EXCLUDED.active_version`, library.Version())
	if err != nil {
		t.Fatal(err)
	}
	identity := normalized.Event{SchemaVersion: "v1", EventID: id + "-identity", Source: "radius", Type: "identity", Timestamp: now.Add(-time.Hour).Format(time.RFC3339Nano), Subject: map[string]any{"endpoint_id": id, "mac": "02:00:00:00:90:08", "ip": "198.18.90.8", "entity_role": "endpoint"}, Payload: map[string]any{}, Flow: map[string]any{}}
	if err := pg.WriteIdentityEvents(ctx, []normalized.Event{identity}); err != nil {
		t.Fatal(err)
	}
	events := brandReplay(t)
	for i := range events {
		events[i].EventID = id + events[i].EventID
		events[i].Subject["endpoint_id"] = id
		events[i].Timestamp = now.Add(time.Duration(i-20) * time.Minute).Format(time.RFC3339Nano)
	}
	for range 2 {
		if _, err := pg.ProcessDomainEvents(ctx, events, library); err != nil {
			t.Fatal(err)
		}
	}
	profile, ok, err := pg.GetEndpointIdentity(ctx, id, Query{})
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if profile.BrandInference == nil || profile.BrandInference.Status != "inferred" || profile.BrandInference.Brand != "Apple" || profile.Recognition.Brand != "" {
		t.Fatalf("unexpected profile %+v", profile)
	}
	evidence, err := pg.windowDomainEvidence(ctx, id, library.Version(), now)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, item := range evidence {
		count += item.Count
	}
	if count != 4 {
		t.Fatalf("duplicate replay count %d", count)
	}
	// All groups, including ones beyond a UI page, remain in the evaluator.
	more := []normalized.Event{}
	for i := 0; i < 205; i++ {
		e := events[1]
		e.EventID = fmt.Sprintf("%s-extra-%d", id, i)
		e.Payload = map[string]any{"sni": fmt.Sprintf("node%d.push.apple.com", i)}
		more = append(more, e)
	}
	if _, err := pg.ProcessDomainEvents(ctx, more, library); err != nil {
		t.Fatal(err)
	}
	evidence, err = pg.windowDomainEvidence(ctx, id, library.Version(), now)
	if err != nil || len(evidence) < 205 {
		t.Fatalf("window truncated: %d %v", len(evidence), err)
	}
	before := profile.Recognition.BrandConfidence
	for range 3 {
		p, _, err := pg.GetEndpointIdentity(ctx, id, Query{})
		if err != nil || p.Recognition.BrandConfidence != before {
			t.Fatalf("confidence drift %v", err)
		}
	}
	future, err := pg.windowDomainEvidence(ctx, id, library.Version(), now.Add(8*24*time.Hour))
	if err != nil || len(future) != 0 {
		t.Fatalf("expiry %v %d", err, len(future))
	}
	other, err := pg.windowDomainEvidence(ctx, id, "other-version", now)
	if err != nil || len(other) != 0 {
		t.Fatal("mixed versions")
	}
	_, err = pg.db.ExecContext(ctx, `UPDATE domain_recognition_state SET pending_version='new-rules' WHERE singleton`)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := pg.GetEndpointIdentity(ctx, id, Query{})
	if err != nil || p.BrandInference.Status != "inferred" {
		t.Fatal("pending version hid active evidence")
	}
	db := &DBStore{pg: pg}
	if err := db.activateDomainVersion(ctx, "superseded"); err == nil {
		t.Fatal("superseded version activated")
	}
	if err := db.activateDomainVersion(ctx, "new-rules"); err != nil {
		t.Fatal(err)
	}
	p, _, err = pg.GetEndpointIdentity(ctx, id, Query{})
	if err != nil || p.BrandInference.Status != "insufficient" {
		t.Fatal("old evidence leaked after activation")
	}
}
