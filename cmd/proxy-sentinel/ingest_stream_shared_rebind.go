package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"proxy-sentinel/internal/streamlog"
)

type sharedStreamRebind struct {
	Sensor, Scope, ScopeHash     string
	Owner, Path, OldEpoch, Epoch string
	Manifest, FileManifest       string
	Cutoff                       time.Time
}

// The unaffected owner keeps its file binding and common job generation.
// The changed owner's epoch fences packet evidence and in-flight decisions.
func rebindStreamSharedSource(ctx context.Context, db *sql.DB, input sharedStreamRebind) error {
	other := "handshake-sidecar"
	if input.Owner == other {
		other = "packet-sidecar"
	} else if input.Owner != "packet-sidecar" {
		return errors.New("invalid shared source owner")
	}
	if input.OldEpoch == "" || input.Epoch == "" || input.OldEpoch == input.Epoch || len(input.ScopeHash) != 64 || len(input.Manifest) != 64 || len(input.FileManifest) != 64 || input.Cutoff.IsZero() {
		return errors.New("shared source rebind requires immutable cutover and audit proof")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var scope, generation, currentEpoch, currentPath string
	var currentCutoff time.Time
	if err = tx.QueryRowContext(ctx, `SELECT scope_id,cancel_id,epoch,source_path,source_cutoff_at FROM stream_shared_source_cutovers
 WHERE sensor_id=$1 AND source_owner=$2 AND state='active' FOR UPDATE`, input.Sensor, input.Owner).
		Scan(&scope, &generation, &currentEpoch, &currentPath, &currentCutoff); err != nil {
		return err
	}
	if scope != input.Scope || currentPath != input.Path || generation == "" || (currentEpoch != input.OldEpoch && currentEpoch != input.Epoch) {
		return streamlog.ErrContentConflict
	}
	var companion bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM stream_shared_source_cutovers s JOIN stream_source_cutovers f USING(epoch,source_kind,source_path)
 WHERE s.sensor_id=$1 AND f.sensor_id=$1 AND s.source_owner=$2 AND s.scope_id=$3 AND s.cancel_id=$4 AND s.state='active' AND f.state='active')`, input.Sensor, other, input.Scope, generation).Scan(&companion); err != nil {
		return err
	}
	if !companion {
		return errors.New("unchanged shared source must have a matching active file binding")
	}
	var oldFileState, newFileState, newScope, newManifest string
	var newCutoff time.Time
	if err = tx.QueryRowContext(ctx, `SELECT state FROM stream_source_cutovers
 WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 AND sensor_id=$3 FOR UPDATE`, input.OldEpoch, input.Path, input.Sensor).Scan(&oldFileState); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT state,capture_scope_sha256,cancel_manifest_sha256,legacy_cutoff_at FROM stream_source_cutovers
 WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 AND sensor_id=$3 FOR UPDATE`, input.Epoch, input.Path, input.Sensor).
		Scan(&newFileState, &newScope, &newManifest, &newCutoff); err != nil {
		return err
	}
	if newScope != input.ScopeHash || newManifest != input.FileManifest || !newCutoff.Equal(input.Cutoff) {
		return streamlog.ErrContentConflict
	}
	// The audit digest ties the approved old-source manifest to the exact new
	// file cutover. It is immutable across retries, even after both row flips.
	proof, err := json.Marshal(input)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(proof)
	digest := hex.EncodeToString(sum[:])
	if currentEpoch == input.Epoch {
		var stored string
		err = tx.QueryRowContext(ctx, `SELECT content_sha256 FROM stream_discard_manifest
 WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 AND legacy_kind='shared_binding_reconciled' AND legacy_reference=$3`, input.OldEpoch, input.Path, input.Epoch).Scan(&stored)
		if err != nil || stored != digest || oldFileState != "closed" || newFileState != "active" {
			return fmt.Errorf("verify committed shared rebind: %w", errors.Join(streamlog.ErrContentConflict, err))
		}
		return tx.Commit()
	}
	if !currentCutoff.Before(input.Cutoff) || !((oldFileState == "active" && newFileState == "prepared") || (oldFileState == "closed" && newFileState == "active")) {
		return streamlog.ErrContentConflict
	}
	if oldFileState == "active" {
		if _, err = tx.ExecContext(ctx, `UPDATE stream_source_cutovers SET state='closed' WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2`, input.OldEpoch, input.Path); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE stream_source_cutovers SET state='active' WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2`, input.Epoch, input.Path); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO stream_discard_manifest
 (epoch,source_kind,source_path,legacy_kind,legacy_reference,legacy_status,content_sha256,unprocessed_records)
 VALUES($1,'device-signals',$2,'shared_binding_reconciled',$3,'binding_reconciled',$4,0)`, input.OldEpoch, input.Path, input.Epoch, digest); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE stream_shared_source_cutovers SET state='closed' WHERE sensor_id=$1 AND source_owner=$2 AND epoch=$3`, input.Sensor, input.Owner, input.OldEpoch); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO stream_shared_source_cutovers
 (sensor_id,source_owner,epoch,source_path,scope_id,source_cutoff_at,cancel_id,canceled_jobs,canceled_manifest_sha256,state)
 VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,'active')`, input.Sensor, input.Owner, input.Epoch, input.Path, input.Scope, input.Cutoff, generation, digest); err != nil {
		return err
	}
	return tx.Commit()
}

func verifySharedRebindManifest(path, expected string) error {
	if path == "" || len(expected) != 64 {
		return errors.New("old source audit manifest and SHA256 are required")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	const maxManifestBytes = 16 << 20
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return err
	}
	if count == 0 || count > maxManifestBytes || hex.EncodeToString(hash.Sum(nil)) != expected {
		return streamlog.ErrContentConflict
	}
	return nil
}
