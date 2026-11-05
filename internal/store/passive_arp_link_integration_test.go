package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

// ARP binds its sender MAC and IP at the event time. It must link that
// observation to the existing MAC endpoint even without a DHCP lease.
func TestPassiveARPLinksEndpointWithoutDHCPLease(t *testing.T) {
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
	store := &DBStore{pg: pg}
	at := time.Now().UTC().Truncate(time.Second)
	id := fmt.Sprintf("passive-arp-link-%d", at.UnixNano())
	otherID := id + "-ssdp"
	mac := "02:00:00:aa:bb:cc"
	endpointID := "mac:" + mac
	t.Cleanup(func() {
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM discovery_identity_links WHERE observation_id=$1`, id)
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM discovery_identity_links WHERE observation_id=$1`, otherID)
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM discovery_observations WHERE id=$1`, id)
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM discovery_observations WHERE id=$1`, otherID)
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, endpointID)
		_, _ = pg.db.ExecContext(ctx, `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, endpointID)
	})
	if _, err = pg.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,attributes) VALUES($1,$2,'endpoint',$3,$3,'{}')`, endpointID, mac, at); err != nil {
		t.Fatal(err)
	}
	observation := discovery.Observation{ID: id, EventID: id, SourceID: "passive:test", Origin: "arp", Node: "sensor-204", Site: "sensor-204", Domain: "mirror", IP: "192.168.50.12", MAC: mac, ObservedAt: at, ValidUntil: at.Add(10 * time.Minute), Evidence: normalized.Event{Subject: map[string]any{"campus_id": "sensor-204"}}}
	if err = store.insertPassiveObservation(ctx, pg.db, observation); err != nil {
		t.Fatal(err)
	}
	var linked string
	if err = pg.db.QueryRowContext(ctx, `SELECT endpoint_id FROM discovery_identity_links WHERE observation_id=$1`, id).Scan(&linked); err != nil || linked != endpointID {
		t.Fatalf("ARP sender link missing: endpoint=%q err=%v", linked, err)
	}
	observation.ID, observation.EventID, observation.Origin = otherID, otherID, "ssdp"
	if err = store.insertPassiveObservation(ctx, pg.db, observation); err != nil {
		t.Fatal(err)
	}
	var otherLinked bool
	if err = pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_identity_links WHERE observation_id=$1)`, otherID).Scan(&otherLinked); err != nil || otherLinked {
		t.Fatalf("SSDP without DHCP lease must stay unlinked: linked=%v err=%v", otherLinked, err)
	}
}
