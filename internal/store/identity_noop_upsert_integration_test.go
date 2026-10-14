package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// A replayed or duplicated event must not rewrite rows with values they already hold.
// PostgreSQL writes a new tuple version, every index entry and the row triggers even when
// the new values equal the old ones, so without the ON CONFLICT ... WHERE guard the field
// re-dirtied the inventory projection and paid a full write for nothing. `xmin` pins the
// row version, which is what the guard is really about — updated_at alone would not prove
// that no work happened.
func TestEntityUpsertSkipsUnchangedRows(t *testing.T) {
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
	seen := time.Now().UTC().Truncate(time.Microsecond)
	endpoint := "mac:02:00:00:00:00:9a"
	item := EndpointEntity{EndpointID: endpoint, PrimaryMAC: "02:00:00:00:00:9a", EntityRole: "endpoint", FirstSeen: seen.Add(-time.Hour).Format(time.RFC3339Nano), LastSeen: seen.Format(time.RFC3339Nano), IdentityConfidence: 0.7}
	write := func(entity EndpointEntity) {
		t.Helper()
		tx, err := pg.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = upsertEndpointEntitiesBatch(ctx, tx, []EndpointEntity{entity}); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	version := func() (string, time.Time) {
		t.Helper()
		var xmin string
		var updated time.Time
		if err := pg.db.QueryRowContext(ctx, `SELECT xmin::text,updated_at FROM endpoint_entities WHERE endpoint_id=$1`, endpoint).Scan(&xmin, &updated); err != nil {
			t.Fatal(err)
		}
		return xmin, updated
	}
	write(item)
	firstVersion, firstUpdated := version()

	write(item)
	repeatedVersion, repeatedUpdated := version()
	if repeatedVersion != firstVersion {
		t.Fatalf("replaying an identical event rewrote the row: xmin %s -> %s", firstVersion, repeatedVersion)
	}
	if !repeatedUpdated.Equal(firstUpdated) {
		t.Fatalf("replaying an identical event moved updated_at: %s -> %s", firstUpdated, repeatedUpdated)
	}

	newer := item
	newer.LastSeen = seen.Add(time.Minute).Format(time.RFC3339Nano)
	write(newer)
	advancedVersion, advancedUpdated := version()
	if advancedVersion == firstVersion {
		t.Fatal("an event that advances last_seen did not update the row")
	}
	if !advancedUpdated.After(firstUpdated) {
		t.Fatalf("last_seen advanced but updated_at did not: %s -> %s", firstUpdated, advancedUpdated)
	}
	var lastSeen time.Time
	if err := pg.db.QueryRowContext(ctx, `SELECT last_seen FROM endpoint_entities WHERE endpoint_id=$1`, endpoint).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	wantLastSeen, err := time.Parse(time.RFC3339Nano, newer.LastSeen)
	if err != nil {
		t.Fatal(err)
	}
	if !lastSeen.UTC().Equal(wantLastSeen.UTC()) {
		t.Fatalf("last_seen not advanced: got %s want %s", lastSeen, wantLastSeen)
	}
}
