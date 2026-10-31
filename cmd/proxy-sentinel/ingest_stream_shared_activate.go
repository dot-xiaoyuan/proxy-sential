package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

type sharedSourceActivation struct{ Owner, Path, Epoch, FileCancelID string }

// Both sidecar owners switch together: the old per-IP job can be woken by
// either owner, so a partial generation would mix two evidence histories.
func runIngestStreamSharedActivate(args []string) error {
	fs := flag.NewFlagSet("ingest stream-shared-activate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sensor := fs.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "registered capture sensor")
	packetPath := fs.String("packet-source", "", "fresh packet-sidecar file")
	packetEpoch := fs.String("packet-epoch", "", "prepared packet-sidecar epoch")
	handshakePath := fs.String("handshake-source", "", "fresh handshake-sidecar file")
	handshakeEpoch := fs.String("handshake-epoch", "", "prepared handshake-sidecar epoch")
	scopeFile := fs.String("capture-scope-config", os.Getenv("PROXY_SENTINEL_CAPTURE_SCOPE_CONFIG"), "controlled capture scope")
	controlledInterface := fs.String("controlled-interface", "", "verified capture interface")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	cancelID := fs.String("cancel-id", "", "immutable fresh generation and old-job cancellation ID")
	previousCancelID := fs.String("previous-cancel-id", "", "closed shared generation whose unfinished jobs must be canceled")
	packetFileCancelID := fs.String("packet-file-cancel-id", "", "audited packet file cutover cancellation ID, when different from the shared generation")
	handshakeFileCancelID := fs.String("handshake-file-cancel-id", "", "audited handshake file cutover cancellation ID, when different from the shared generation")
	recoverClosedFiles := fs.Bool("recover-closed-file-generation", false, "audit and close a stale shared generation whose file cutovers are already closed")
	cutoffText := fs.String("cutoff-at", "", "fixed old-input cutoff")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *sensor == "" || *packetPath == "" || *packetEpoch == "" || *handshakePath == "" || *handshakeEpoch == "" || *packetPath == *handshakePath || *packetEpoch == *handshakeEpoch || *scopeFile == "" || *postgresDSN == "" || *cancelID == "" || *cutoffText == "" {
		return errors.New("shared activation needs two distinct audited sources, scope, generation and database")
	}
	cutoff, err := time.Parse(time.RFC3339Nano, *cutoffText)
	if err != nil || cutoff.After(time.Now()) {
		return errors.New("invalid shared old-input cutoff")
	}
	scope, scopeHash, err := loadCaptureScopeWithHash(*scopeFile)
	if err != nil {
		return err
	}
	if scope == nil || scope.SensorID != *sensor || time.Now().Before(scope.ValidFrom) || !time.Now().Before(scope.ValidUntil) {
		return errors.New("shared activation scope is invalid or expired")
	}
	if *controlledInterface == "" {
		*controlledInterface = scope.InterfaceName
	}
	if *controlledInterface == "" || (scope.InterfaceName != "" && *controlledInterface != scope.InterfaceName) {
		return errors.New("shared activation interface differs from source scope")
	}
	scopeHash = controlledScopeBindingHash(scopeHash, *controlledInterface)
	sources := []sharedSourceActivation{{"handshake-sidecar", *handshakePath, *handshakeEpoch, *handshakeFileCancelID}, {"packet-sidecar", *packetPath, *packetEpoch, *packetFileCancelID}}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	leaseStore, err := store.NewPostgresStore(store.PostgresOptions{DSN: *postgresDSN, SensorID: *sensor})
	if err != nil {
		return err
	}
	defer leaseStore.Close()
	releases := []func(){}
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()
	for _, src := range sources {
		release, err := leaseStore.AcquireIngestSourceLease(ctx, "device-signals", src.Path)
		if err != nil {
			return err
		}
		releases = append(releases, release)
	}
	db, err := sql.Open("pgx", *postgresDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(store.PostgresPoolLimit(2))
	if *recoverClosedFiles {
		if *previousCancelID == "" {
			return errors.New("stale shared generation recovery requires previous-cancel-id")
		}
		if err := recoverClosedFileSharedGeneration(ctx, db, *sensor, sources, *previousCancelID, *cancelID, cutoff); err != nil {
			return err
		}
	}
	if err := activateStreamSharedSources(ctx, db, *sensor, scope, scopeHash, sources, *cancelID, cutoff, *previousCancelID); err != nil {
		return err
	}
	manifest, counts, err := readSharedCancellationManifest(ctx, db, *sensor, sources, *cancelID, cutoff, scope.ID())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"sensor_id": *sensor, "cancel_id": *cancelID, "cutoff_at": cutoff, "source_epochs": sources, "canceled_jobs": counts, "manifest_sha256": manifest})
}

func activateStreamSharedSources(ctx context.Context, db *sql.DB, sensor string, scope *normalized.CaptureScope, scopeHash string, sources []sharedSourceActivation, cancelID string, cutoff time.Time, previous ...string) error {
	if db == nil || scope == nil || sensor == "" || len(sources) != 2 || cancelID == "" || len(scopeHash) != 64 || cutoff.IsZero() || scope.ID() == "" {
		return errors.New("invalid shared source activation")
	}
	oldGeneration := ""
	if len(previous) > 1 {
		return errors.New("multiple previous shared generations")
	}
	if len(previous) == 1 {
		oldGeneration = previous[0]
	}
	if oldGeneration == cancelID {
		return errors.New("new shared generation must differ from the retired generation")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, src := range sources {
		if oldGeneration != "" {
			var retired int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM stream_shared_source_cutovers WHERE sensor_id=$1 AND source_owner=$2 AND source_path=$3 AND cancel_id=$4 AND state='closed'`, sensor, src.Owner, src.Path, oldGeneration).Scan(&retired); err != nil {
				return err
			}
			if retired != 1 {
				return errors.New("prior shared source is not uniquely closed")
			}
		}
		var recordedSensor, recordedHash, recordedCancel, state string
		var recordedCutoff time.Time
		err = tx.QueryRowContext(ctx, `SELECT sensor_id,capture_scope_sha256,legacy_cancel_id,state,legacy_cutoff_at FROM stream_source_cutovers
 WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 FOR UPDATE`, src.Epoch, src.Path).Scan(&recordedSensor, &recordedHash, &recordedCancel, &state, &recordedCutoff)
		if err != nil {
			return err
		}
		fileCancelID := src.FileCancelID
		if fileCancelID == "" {
			fileCancelID = cancelID
		}
		if recordedSensor != sensor || recordedHash != scopeHash || recordedCancel != fileCancelID || state != "active" || !recordedCutoff.Equal(cutoff) {
			return errors.New("shared source does not match an active audited file cutover")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO stream_shared_source_cutovers(sensor_id,source_owner,epoch,source_path,scope_id,source_cutoff_at,cancel_id,canceled_jobs,canceled_manifest_sha256,state)
 VALUES($1,$2,$3,$4,$5,$6,$7,0,repeat('0',64),'prepared') ON CONFLICT DO NOTHING`, sensor, src.Owner, src.Epoch, src.Path, scope.ID(), cutoff, cancelID)
		if err != nil {
			return err
		}
		var existingPath, existingScope, existingCancel, existingState string
		var existingCutoff time.Time
		err = tx.QueryRowContext(ctx, `SELECT source_path,scope_id,source_cutoff_at,cancel_id,state FROM stream_shared_source_cutovers WHERE sensor_id=$1 AND source_owner=$2 AND epoch=$3 FOR UPDATE`, sensor, src.Owner, src.Epoch).Scan(&existingPath, &existingScope, &existingCutoff, &existingCancel, &existingState)
		if err != nil {
			return err
		}
		if existingPath != src.Path || existingScope != scope.ID() || !existingCutoff.Equal(cutoff) || existingCancel != cancelID || (existingState != "prepared" && existingState != "active") {
			return errors.New("shared cutover preparation conflicts with stored generation")
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, src := range sources {
		kind, table := "ip", "shared_observation_jobs"
		if src.Owner == "packet-sidecar" {
			kind, table = "gateway", "shared_gateway_observation_jobs"
		}
		for {
			query := fmt.Sprintf(`WITH picked AS (SELECT job_id,revision,last_event_at,dirty_since FROM %s
 WHERE sensor_id=$1 AND generation_id IN ('',$5) AND canceled_epoch='' AND revision>completed_revision AND NOT expired
 ORDER BY job_id LIMIT 500 FOR UPDATE), marked AS (
	 UPDATE %s j SET canceled_epoch=$2%s FROM picked p WHERE j.job_id=p.job_id
 RETURNING j.job_id,j.revision,j.last_event_at,j.dirty_since)
 INSERT INTO stream_shared_canceled_jobs(sensor_id,source_owner,epoch,job_kind,job_id,canceled_revision,last_event_at,dirty_since)
	 SELECT $1,$3,$2,$4,job_id,revision,last_event_at,dirty_since FROM marked`, table, table, map[bool]string{true: ",lease_token='',lease_until=NULL", false: ""}[src.Owner == "handshake-sidecar"])
			result, err := db.ExecContext(ctx, query, sensor, src.Epoch, src.Owner, kind, oldGeneration)
			if err != nil {
				return err
			}
			count, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if count == 0 {
				break
			}
		}
	}
	manifest, counts, err := readSharedCancellationManifest(ctx, db, sensor, sources, cancelID, cutoff, scope.ID())
	if err != nil {
		return err
	}
	final, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer final.Rollback()
	for _, src := range sources {
		table := "shared_observation_jobs"
		if src.Owner == "packet-sidecar" {
			table = "shared_gateway_observation_jobs"
		}
		var pending bool
		if err := final.QueryRowContext(ctx, fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE sensor_id=$1 AND generation_id IN ('',$2) AND canceled_epoch='' AND revision>completed_revision AND NOT expired LIMIT 1)`, table), sensor, oldGeneration).Scan(&pending); err != nil {
			return err
		}
		if pending {
			return errors.New("old shared work appeared during activation")
		}
		result, err := final.ExecContext(ctx, `UPDATE stream_shared_source_cutovers SET canceled_jobs=$4,canceled_manifest_sha256=$5,state='active'
 WHERE sensor_id=$1 AND source_owner=$2 AND epoch=$3 AND cancel_id=$6 AND state IN ('prepared','active')`, sensor, src.Owner, src.Epoch, counts[src.Owner], manifest, cancelID)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return errors.New("shared source activation lost its prepared row")
		}
	}
	return final.Commit()
}

// A file-only history reset can leave the shared generation pointing at a
// closed file epoch. Recover it only after checking both immutable file
// cutovers, and record the exact old/new epoch pair in the existing audit
// ledger. The subsequent activation cancels unfinished old-generation jobs.
func recoverClosedFileSharedGeneration(ctx context.Context, db *sql.DB, sensor string, sources []sharedSourceActivation, oldGeneration, newGeneration string, cutoff time.Time) error {
	if db == nil || sensor == "" || len(sources) != 2 || oldGeneration == "" || newGeneration == "" || oldGeneration == newGeneration || cutoff.IsZero() {
		return errors.New("invalid stale shared generation recovery")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, src := range sources {
		if src.Owner != "packet-sidecar" && src.Owner != "handshake-sidecar" || src.Path == "" || src.Epoch == "" {
			return errors.New("invalid shared recovery source")
		}
		var oldEpoch, oldState, fileState, fileManifest string
		var oldCutoff time.Time
		err := tx.QueryRowContext(ctx, `SELECT s.epoch,s.state,f.state,f.cancel_manifest_sha256,s.source_cutoff_at
 FROM stream_shared_source_cutovers s JOIN stream_source_cutovers f
 ON f.epoch=s.epoch AND f.source_kind='device-signals' AND f.source_path=s.source_path
 WHERE s.sensor_id=$1 AND s.source_owner=$2 AND s.source_path=$3 AND s.cancel_id=$4
 ORDER BY s.source_cutoff_at DESC LIMIT 1 FOR UPDATE OF s`, sensor, src.Owner, src.Path, oldGeneration).Scan(&oldEpoch, &oldState, &fileState, &fileManifest, &oldCutoff)
		if err != nil {
			return err
		}
		if oldEpoch == src.Epoch || (oldState != "active" && oldState != "closed") || fileState != "closed" || len(fileManifest) != 64 || !oldCutoff.Before(cutoff) {
			return errors.New("previous shared generation has no closed audited file cutover")
		}
		var newSensor, newState, fileCancel string
		var newCutoff time.Time
		err = tx.QueryRowContext(ctx, `SELECT sensor_id,state,legacy_cancel_id,legacy_cutoff_at FROM stream_source_cutovers
 WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 FOR UPDATE`, src.Epoch, src.Path).Scan(&newSensor, &newState, &fileCancel, &newCutoff)
		if err != nil {
			return err
		}
		expectedFileCancel := src.FileCancelID
		if expectedFileCancel == "" {
			expectedFileCancel = newGeneration
		}
		if newSensor != sensor || newState != "active" || fileCancel != expectedFileCancel || !newCutoff.Equal(cutoff) {
			return errors.New("new shared recovery source does not match its active file cutover")
		}
		encoded, err := json.Marshal([]string{sensor, src.Owner, src.Path, oldEpoch, oldGeneration, fileManifest, src.Epoch, fileCancel, newGeneration, cutoff.UTC().Format(time.RFC3339Nano)})
		if err != nil {
			return err
		}
		hash := sha256.Sum256(encoded)
		manifest := hex.EncodeToString(hash[:])
		if _, err := tx.ExecContext(ctx, `INSERT INTO stream_discard_manifest
 (epoch,source_kind,source_path,legacy_kind,legacy_reference,legacy_status,content_sha256,unprocessed_records)
 VALUES($1,'device-signals',$2,'shared_generation_reconciled',$3,'closed_audited',$4,0)
 ON CONFLICT DO NOTHING`, oldEpoch, src.Path, src.Epoch, manifest); err != nil {
			return err
		}
		var stored string
		if err := tx.QueryRowContext(ctx, `SELECT content_sha256 FROM stream_discard_manifest
 WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2
 AND legacy_kind='shared_generation_reconciled' AND legacy_reference=$3`, oldEpoch, src.Path, src.Epoch).Scan(&stored); err != nil {
			return err
		}
		if stored != manifest {
			return errors.New("shared generation recovery audit differs from stored record")
		}
		if oldState == "active" {
			result, err := tx.ExecContext(ctx, `UPDATE stream_shared_source_cutovers SET state='closed'
 WHERE sensor_id=$1 AND source_owner=$2 AND epoch=$3 AND cancel_id=$4 AND state='active'`, sensor, src.Owner, oldEpoch, oldGeneration)
			if err != nil {
				return err
			}
			if changed, err := result.RowsAffected(); err != nil || changed != 1 {
				return errors.New("shared generation changed during recovery")
			}
		}
	}
	return tx.Commit()
}

func readSharedCancellationManifest(ctx context.Context, db *sql.DB, sensor string, sources []sharedSourceActivation, cancelID string, cutoff time.Time, scopeID string) (string, map[string]int64, error) {
	h := sha256.New()
	for _, field := range []string{sensor, cancelID, cutoff.UTC().Format(time.RFC3339Nano), scopeID} {
		io.WriteString(h, field)
		h.Write([]byte{0})
	}
	ordered := append([]sharedSourceActivation(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Owner < ordered[j].Owner })
	for _, src := range ordered {
		for _, field := range []string{src.Owner, src.Path, src.Epoch} {
			io.WriteString(h, field)
			h.Write([]byte{0})
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT source_owner,epoch,job_kind,job_id,canceled_revision,last_event_at,dirty_since
	 FROM stream_shared_canceled_jobs WHERE sensor_id=$1 AND epoch IN ($2,$3) ORDER BY source_owner,job_kind,job_id`, sensor, ordered[0].Epoch, ordered[1].Epoch)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	counts := map[string]int64{"handshake-sidecar": 0, "packet-sidecar": 0}
	for rows.Next() {
		var owner, epoch, kind, id string
		var revision int64
		var at, dirty time.Time
		if err := rows.Scan(&owner, &epoch, &kind, &id, &revision, &at, &dirty); err != nil {
			return "", nil, err
		}
		if owner != "handshake-sidecar" && owner != "packet-sidecar" {
			return "", nil, errors.New("unexpected shared cancellation owner")
		}
		for _, field := range []string{owner, epoch, kind, id, fmt.Sprint(revision), at.UTC().Format(time.RFC3339Nano), dirty.UTC().Format(time.RFC3339Nano)} {
			io.WriteString(h, field)
			h.Write([]byte{0})
		}
		counts[owner]++
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(h.Sum(nil)), counts, nil
}
