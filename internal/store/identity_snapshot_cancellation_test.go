package store

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5"
)

func TestSnapshotProjectorExcludesAuditedCancellationBeforeLoadingRaw(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT f.document.*NOT EXISTS\(SELECT 1 FROM identity_snapshot_projection_cancellations.*ORDER BY j.observed_at`).
		WillReturnRows(sqlmock.NewRows([]string{"document"}))
	mock.ExpectRollback()
	store := &PostgresStore{db: db}
	if err := store.projectPendingIdentitySnapshots(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelledSnapshotKeepsEvidenceAndProjectsNewerPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_SNAPSHOT_CANCEL_DSN")
	if dsn == "" {
		t.Skip("dedicated disposable snapshot-cancellation PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(cfg.Database, "_snapshot_cancel_test") || len(cfg.Fallbacks) > 0 {
		t.Fatal("snapshot cancellation replay requires a dedicated disposable test database without fallback hosts")
	}
	host := strings.ToLower(cfg.Host)
	if host == "" || host == "localhost" || strings.HasPrefix(host, "/") {
		t.Fatal("snapshot cancellation replay refuses a local or unspecified database host")
	}
	resolved, err := net.LookupIP(host)
	if err != nil {
		t.Fatal(err)
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	local := make([]net.IP, 0, len(interfaces))
	for _, address := range interfaces {
		switch value := address.(type) {
		case *net.IPNet:
			local = append(local, value.IP)
		case *net.IPAddr:
			local = append(local, value.IP)
		}
	}
	for _, address := range resolved {
		if identityReadyForbiddenAddress(address, local) {
			t.Fatal("snapshot cancellation replay refuses a local or 184 database host")
		}
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
	scope := IdentityScope{Source: "ncu-srun4k", SensorID: fmt.Sprintf("cancel-%d", time.Now().UnixNano()), CampusID: "ncu", AccessDomain: "campus-auth"}
	// Earlier than other integration fixtures so the global queue claims this pair first.
	base := time.Unix(1, 0).UTC()
	oldID, newID := fmt.Sprintf("old-%d", time.Now().UnixNano()), fmt.Sprintf("new-%d", time.Now().UnixNano())
	old := IdentitySnapshot{IdentityScope: scope, SnapshotID: oldID, ObservedAt: base, IntervalSeconds: 1800}
	newer := IdentitySnapshot{IdentityScope: scope, SnapshotID: newID, ObservedAt: base.Add(time.Minute), IntervalSeconds: 1800}
	for _, snapshot := range []IdentitySnapshot{old, newer} {
		if _, err := pg.CommitIdentitySnapshot(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
	}
	var originalHash string
	err = pg.db.QueryRowContext(ctx, `SELECT content_sha256 FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain, oldID).Scan(&originalHash)
	if err != nil {
		t.Fatal(err)
	}
	newEpoch := fmt.Sprintf("snapshot-cancel-epoch-%d", time.Now().UnixNano())
	_, err = pg.db.ExecContext(ctx, `INSERT INTO identity_fresh_recovery_gaps
 (new_epoch,old_epoch,scope_key,old_start_offset,accepted_sequence,processed_sequence,
 legacy_pending_records,legacy_export_pending_records,retained_batch_count,retained_fragment_count,
 retained_ready_count,retained_pending_ip_count,old_legacy_cancel_id,old_cancel_manifest_sha256,
 redis_event_list,redis_processing_list,redis_source_length,redis_processing_length,redis_sample_at,
 redis_boundary,redis_audit_sha256,audit_sha256,reason)
 VALUES($1,'test-old-epoch',$2,0,0,0,0,0,0,0,0,0,'test-cancel',$3,
 'test-source','test-processing',0,0,now(),'{}'::jsonb,$3,$3,'test snapshot cancellation boundary')`, newEpoch, IdentityScopeKey(scope), originalHash)
	if err != nil {
		t.Fatal(err)
	}
	cutoverAt := time.Now().UTC().Add(time.Minute)
	_, err = pg.db.ExecContext(ctx, `INSERT INTO identity_snapshot_projection_cancellations(source,sensor_id,campus_id,access_domain,snapshot_id,new_epoch,cutover_at,observed_at,received_at,content_sha256,reason)
	 SELECT f.source,f.sensor_id,f.campus_id,f.access_domain,f.snapshot_id,$1,$2,f.observed_at,f.received_at,f.content_sha256,'test abandoned old snapshot'
	 FROM identity_full_snapshots f WHERE f.source=$3 AND f.sensor_id=$4 AND f.campus_id=$5 AND f.access_domain=$6 AND f.snapshot_id=$7`, newEpoch, cutoverAt, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain, oldID)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.projectPendingIdentitySnapshots(ctx, 1); err != nil {
		t.Fatal(err)
	}
	var oldJob, oldRaw, newJob, newProjected, oldProjected bool
	err = pg.db.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM identity_snapshot_projection_jobs WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5),
 EXISTS(SELECT 1 FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5 AND content_sha256=$7),
 EXISTS(SELECT 1 FROM identity_snapshot_projection_jobs WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$6),
 (SELECT projected FROM identity_snapshot_log WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$6),
 (SELECT projected FROM identity_snapshot_log WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5)`, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain, oldID, newID, originalHash).Scan(&oldJob, &oldRaw, &newJob, &newProjected, &oldProjected)
	if err != nil {
		t.Fatal(err)
	}
	if !oldJob || !oldRaw || newJob || !newProjected || oldProjected {
		t.Fatalf("old job/raw=%t/%t, new job/projected=%t/%t, old projected=%t", oldJob, oldRaw, newJob, newProjected, oldProjected)
	}
	if _, err := pg.db.ExecContext(ctx, `DELETE FROM identity_snapshot_projection_jobs WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain, oldID); err == nil {
		t.Fatal("cancelled job deleted")
	}
	if _, err := pg.db.ExecContext(ctx, `UPDATE identity_full_snapshots SET content_sha256=$6 WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain, oldID, originalHash); err == nil {
		t.Fatal("cancelled full snapshot rewritten")
	}
	if _, err := pg.db.ExecContext(ctx, `UPDATE identity_snapshot_log SET projected=true WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain, oldID); err == nil {
		t.Fatal("cancelled log marked projected")
	}
	if _, err := pg.db.ExecContext(ctx, `UPDATE identity_snapshot_projection_cancellations SET reason='changed' WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain, oldID); err == nil {
		t.Fatal("immutable audit changed")
	}
	var pending, cancelled int64
	err = pg.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity_snapshot_projection_jobs j WHERE j.sensor_id=$1 AND NOT EXISTS(SELECT 1 FROM identity_snapshot_projection_cancellations c WHERE c.source=j.source AND c.sensor_id=j.sensor_id AND c.campus_id=j.campus_id AND c.access_domain=j.access_domain AND c.snapshot_id=j.snapshot_id)),(SELECT count(*) FROM identity_snapshot_projection_cancellations WHERE sensor_id=$1)`, scope.SensorID).Scan(&pending, &cancelled)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 0 || cancelled != 1 {
		t.Fatalf("pending=%d cancelled=%d", pending, cancelled)
	}
}
