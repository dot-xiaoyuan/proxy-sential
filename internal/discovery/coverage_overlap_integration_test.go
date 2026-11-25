package discovery

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// The overlap must use exactly the device and mirror address sets that feed
// ipv4 and mirror_funnel.ipv4_total, so the report can state their union.
func TestCoverageMirrorOverlapMatchesBothReportedAddressSets(t *testing.T) {
	db := coverageOverlapReplayDB(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	from := now.Add(-24 * time.Hour)
	mirrorUntil := now.Add(-2 * time.Minute)
	mirrorFrom := mirrorUntil.Add(-24 * time.Hour)
	device := func(key, node, ip string, at time.Time, withdrawn bool) {
		t.Helper()
		if _, e := db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,'src','arp','','',$1,$2,$2,$3,jsonb_build_object('node',$4::text,'ip',$5::text))`, key, at, withdrawn, node, ip); e != nil {
			t.Fatal(e)
		}
	}
	mirror := func(scope, kind, value string, family int, at time.Time) {
		t.Helper()
		if _, e := db.Exec(`INSERT INTO passive_census_identifier_current(scope_key,sensor_id,kind,value,ip_family,first_seen,last_seen,last_event_id,last_source) VALUES($1,'campus-204',$2,$3,$4,$5,$5,'e','capture')`, scope, kind, value, family, at); e != nil {
			t.Fatal(e)
		}
	}
	recent := now.Add(-time.Hour)
	device("d1", "campus-204", "10.0.0.1", recent, false)
	device("d1b", "campus-204", "10.0.0.1", recent, false)                // same address, second identity
	device("d2", "campus-204", "10.0.0.2", recent, true)                  // withdrawn
	device("d3", "campus-204", "10.0.0.3", now.Add(-25*time.Hour), false) // outside device window
	device("d4", "campus-other", "10.0.0.4", recent, false)               // other sensor
	device("d5", "campus-204", "fe80::1", recent, false)                  // IPv6
	device("d6", "campus-204", "10.0.0.6", recent, false)
	device("d7", "campus-204", "10.0.0.7", recent, false)
	mirror("scope-a", "ip", "10.0.0.1", 4, recent)
	mirror("scope-b", "ip", "10.0.0.1", 4, recent) // same address in another scope
	mirror("scope-a", "ip", "10.0.0.2", 4, recent)
	mirror("scope-a", "ip", "10.0.0.3", 4, recent)
	mirror("scope-a", "ip", "10.0.0.4", 4, recent)
	mirror("scope-a", "ip", "fe80::1", 6, recent)
	mirror("scope-a", "ip", "10.0.0.6", 4, now.Add(-26*time.Hour)) // outside mirror window
	mirror("scope-a", "mac", "10.0.0.7", 0, recent)                // not an IP identifier
	mirror("scope-a", "ip", "10.0.0.9", 4, recent)                 // mirror only
	device("lower", "campus-204", "10.0.0.10", from, false)
	device("upper", "campus-204", "10.0.0.11", now, false)
	mirror("scope-a", "ip", "10.0.0.10", 4, mirrorFrom)
	mirror("scope-a", "ip", "10.0.0.11", 4, mirrorUntil)
	mirror("scope-a", "ip", "10.0.0.12", 4, mirrorUntil.Add(time.Microsecond))

	read := func() CoverageReport {
		t.Helper()
		var out CoverageReport
		if err := coverageAddressAndMirrorCounts(context.Background(), db, "campus-204", 24*time.Hour, now, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := read(); out.IPv4 != 4 || out.MirrorFunnel.AsOf != nil || out.IPv4MirrorOverlap != nil {
		t.Fatalf("uninitialized census: %+v", out)
	}
	if _, err := db.Exec(`INSERT INTO passive_census_runtime(sensor_id,last_source_at,available_from) VALUES('campus-204',$1,$2)`, mirrorUntil, mirrorFrom); err != nil {
		t.Fatal(err)
	}
	out := read()
	if out.IPv4 != 4 || out.MirrorFunnel.IPv4Total != 7 || out.IPv4MirrorOverlap == nil || *out.IPv4MirrorOverlap != 2 || out.IPv4+out.MirrorFunnel.IPv4Total-*out.IPv4MirrorOverlap != 9 {
		t.Fatalf("device/mirror/intersection = %d/%d/%v, want 4/7/2 and union 9", out.IPv4, out.MirrorFunnel.IPv4Total, out.IPv4MirrorOverlap)
	}
	if _, err := db.Exec(`UPDATE discovery_observation_latest SET withdrawn=true`); err != nil {
		t.Fatal(err)
	}
	if out := read(); out.IPv4 != 0 || out.IPv4MirrorOverlap == nil || *out.IPv4MirrorOverlap != 0 {
		t.Fatalf("observed empty intersection: %+v", out)
	}
}

func coverageOverlapReplayDB(t *testing.T) *sql.DB {
	t.Helper()
	db := legacyDiscoveryReplayDB(t)
	applyDiscoveryTestSQL(t, db, "235_passive_census_projection.sql", "241_passive_hardware_projection.sql")
	return db
}

// The reader sees the census watermark before it sees the identifier rows.
// Commit a replacement while the watermark query is blocked on its test gate.
func TestCoverageMirrorOverlapUsesWatermarkSnapshot(t *testing.T) {
	db := coverageOverlapReplayDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	at := time.Now().UTC().Truncate(time.Second)
	if _, err := db.Exec(`INSERT INTO discovery_observation_latest VALUES('d','src','arp','','','e',now()-interval '5 minutes',now(),false,'{"node":"sensor","ip":"192.0.2.1"}');
INSERT INTO passive_census_identifier_current(scope_key,sensor_id,kind,value,ip_family,first_seen,last_seen,last_event_id,last_source)
VALUES('scope','sensor','ip','192.0.2.2',4,now()-interval '5 minutes',now()-interval '5 minutes','e','capture')`); err != nil {
		t.Fatal(err)
	}
	writer, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	var key int
	if err = writer.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&key); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", key); err != nil {
		t.Fatal(err)
	}
	// Expose the real runtime row through a view so the writer can wait until
	// the first SELECT has acquired its snapshot without adding a Go test hook.
	if _, err = db.Exec(`INSERT INTO passive_census_runtime(sensor_id,last_source_at) VALUES('sensor',$1)`, at); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(fmt.Sprintf(`ALTER TABLE passive_census_runtime RENAME TO census_runtime_data;
CREATE VIEW passive_census_runtime AS SELECT r.* FROM census_runtime_data r CROSS JOIN pg_advisory_xact_lock_shared(%d::bigint)`, key)); err != nil {
		t.Fatal(err)
	}
	var out CoverageReport
	done := make(chan error, 1)
	go func() { done <- coverageAddressAndMirrorCounts(ctx, db, "sensor", time.Hour, at, &out) }()
	for {
		var waiting bool
		if err := writer.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=$1 AND NOT granted)`, key).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("report returned before writer committed: %v", err)
		case <-time.After(5 * time.Millisecond):
		}
	}
	if _, err = writer.ExecContext(ctx, `UPDATE passive_census_identifier_current SET value='192.0.2.1';
INSERT INTO passive_census_identifier_current(scope_key,sensor_id,kind,value,ip_family,first_seen,last_seen,last_event_id,last_source)
SELECT scope_key,sensor_id,kind,'192.0.2.3',ip_family,first_seen,last_seen,last_event_id,last_source FROM passive_census_identifier_current`); err != nil {
		t.Fatal(err)
	}
	if err = writer.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if out.IPv4 != 1 || out.MirrorFunnel.IPv4Total != 1 || out.IPv4MirrorOverlap == nil || *out.IPv4MirrorOverlap != 0 {
		t.Fatalf("mixed snapshots: %+v", out)
	}
	var after CoverageReport
	if err = coverageAddressAndMirrorCounts(ctx, db, "sensor", time.Hour, at, &after); err != nil {
		t.Fatal(err)
	}
	if after.IPv4 != 1 || after.MirrorFunnel.IPv4Total != 2 || after.IPv4MirrorOverlap == nil || *after.IPv4MirrorOverlap != 1 {
		t.Fatalf("new snapshot: %+v", after)
	}
}

func TestCoverageMirrorOverlapOptionalFailurePreservesTotals(t *testing.T) {
	db := coverageOverlapReplayDB(t)
	// Fault only the query that requests the intersection. A savepoint should
	// allow the existing totals to succeed in this read-only transaction.
	if _, err := db.Exec(`INSERT INTO discovery_observation_latest VALUES('d','src','arp','','','e',now()-interval '5 minutes',now(),false,'{"node":"sensor","ip":"192.0.2.1"}');
INSERT INTO passive_census_runtime(sensor_id,last_source_at) VALUES('sensor',now());
INSERT INTO passive_census_identifier_current(scope_key,sensor_id,kind,value,ip_family,first_seen,last_seen,last_event_id,last_source)
VALUES('scope','sensor','ip','192.0.2.1',4,now()-interval '5 minutes',now()-interval '5 minutes','e','capture');
ALTER TABLE discovery_observation_latest RENAME TO discovery_latest_data;
CREATE FUNCTION test_overlap_failure() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
 IF position('JOIN ips m USING(ip)' in current_query())>0 THEN RAISE EXCEPTION 'test overlap failure'; END IF;
 RETURN true;
END $$;
CREATE VIEW discovery_observation_latest AS SELECT * FROM discovery_latest_data WHERE test_overlap_failure()`); err != nil {
		t.Fatal(err)
	}
	var report CoverageReport
	if err := coverageAddressAndMirrorCounts(context.Background(), db, "sensor", time.Hour, time.Now().UTC(), &report); err != nil {
		t.Fatal(err)
	}
	if report.IPv4 != 1 || report.MirrorFunnel.IPv4Total != 1 || report.IPv4MirrorOverlap != nil {
		t.Fatalf("failed optional read corrupted totals: %+v", report)
	}
	if _, err := db.Exec("DROP VIEW discovery_observation_latest"); err != nil {
		t.Fatal(err)
	}
	if err := coverageAddressAndMirrorCounts(context.Background(), db, "sensor", time.Hour, time.Now().UTC(), &CoverageReport{}); err == nil {
		t.Fatal("required device read failure was hidden")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := coverageAddressAndMirrorCounts(ctx, db, "sensor", time.Hour, time.Now().UTC(), &CoverageReport{}); err != context.Canceled {
		t.Fatalf("context cancellation: %v", err)
	}
}
