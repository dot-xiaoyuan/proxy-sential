package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"proxy-sentinel/internal/normalized"
)

type passiveDiscoveryV3Claim struct {
	ID, Sensor, Owner, Hash string
	Offset, Count           int
	Verified                bool
	ArchiveVerified         bool
	Accepted                time.Time
}

type passiveDiscoveryV3HashRow struct {
	Ordinal int    `json:"ordinal"`
	EventID string `json:"event_id"`
	Hash    string `json:"event_content_sha256"`
}

type passiveDiscoveryV3Row struct {
	Ordinal  int    `json:"ordinal"`
	Hash     string `json:"event_content_sha256"`
	Document string `json:"event_json"`
}

// The old event-time reader must first cross the fixed beginning of the new
// source batches. Until then, the worker keeps draining its old cursor and the
// new batches remain an audited overlap, including late event timestamps.
func (s *DBStore) passiveDiscoveryV3CutoverReady(ctx context.Context, sensor string) (bool, error) {
	alreadyActive, err := s.passiveDiscoveryV3Active(ctx)
	if err != nil {
		return false, err
	}
	if alreadyActive {
		return true, nil
	}
	var first, cursor sql.NullTime
	err = s.pg.db.QueryRowContext(ctx, `SELECT
 (SELECT min(p.first_ingested_at) FROM passive_discovery_batch_progress p JOIN ingest_batches b USING(batch_id)
  WHERE b.sensor_id=$1 AND p.selected_count>0 AND p.first_ingested_at IS NOT NULL),
 (SELECT cursor_timestamp FROM passive_discovery_state WHERE sensor_id=$1)`, sensor).Scan(&first, &cursor)
	if err != nil || !first.Valid || !cursor.Valid || cursor.Time.Before(first.Time) {
		return false, err
	}
	var gaps int
	err = s.pg.db.QueryRowContext(ctx, `SELECT count(*) FROM passive_discovery_batch_progress p JOIN ingest_batches b USING(batch_id)
WHERE b.sensor_id=$1 AND p.selected_count>0 AND p.first_ingested_at<=$2 AND (p.verified_at IS NULL OR p.archive_verified_at IS NULL)`, sensor, cursor.Time).Scan(&gaps)
	return gaps == 0, err
}

func (s *DBStore) passiveDiscoveryV3Active(ctx context.Context) (bool, error) {
	var active bool
	err := s.pg.db.QueryRowContext(ctx, `SELECT COALESCE((state->>'active')::boolean,false) FROM read_model_runtime_state WHERE name='passive-discovery-batch-v3'`).Scan(&active)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return active, err
}

func (s *DBStore) claimPassiveDiscoveryV3(ctx context.Context, sensor string, shadow bool) (passiveDiscoveryV3Claim, bool, error) {
	var claim passiveDiscoveryV3Claim
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return claim, false, err
	}
	claim.Owner = hex.EncodeToString(token[:])
	err := s.pg.db.QueryRowContext(ctx, `WITH picked AS (
 SELECT p.batch_id FROM passive_discovery_batch_progress p JOIN ingest_batches b USING(batch_id)
 WHERE b.status='committed' AND b.sensor_id=$3 AND p.first_ingested_at IS NOT NULL AND p.completed_at IS NULL
 AND p.next_attempt_at<=now() AND p.lease_until<=now() AND (NOT $2::boolean OR p.verified_at IS NULL OR p.archive_verified_at IS NULL)
 ORDER BY p.first_ingested_at,p.batch_id FOR UPDATE OF p SKIP LOCKED LIMIT 1)
UPDATE passive_discovery_batch_progress p SET lease_owner=$1,lease_until=now()+interval '90 seconds',updated_at=now()
FROM picked k,ingest_batches b WHERE p.batch_id=k.batch_id AND b.batch_id=p.batch_id
RETURNING p.batch_id,b.sensor_id,p.selected_count,p.selection_sha256,p.processed_offset,p.verified_at IS NOT NULL,p.archive_verified_at IS NOT NULL,p.first_ingested_at`, claim.Owner, shadow, sensor).Scan(&claim.ID, &claim.Sensor, &claim.Count, &claim.Hash, &claim.Offset, &claim.Verified, &claim.ArchiveVerified, &claim.Accepted)
	if err == sql.ErrNoRows {
		return claim, false, nil
	}
	return claim, err == nil, err
}

func passiveDiscoveryV3ManifestHash(rows []passiveDiscoveryV3HashRow, expected int) (string, error) {
	if len(rows) != expected {
		return "", fmt.Errorf("discovery input v3 has %d rows, expected %d", len(rows), expected)
	}
	h := sha256.New()
	for i, row := range rows {
		if row.Ordinal != i || row.EventID == "" || len(row.Hash) != 64 {
			return "", fmt.Errorf("discovery input v3 ordinal/hash mismatch at %d", i)
		}
		h.Write([]byte(strconv.Itoa(i)))
		h.Write([]byte{0})
		h.Write([]byte(row.EventID))
		h.Write([]byte{0})
		h.Write([]byte(row.Hash))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *DBStore) verifyPassiveDiscoveryV3(ctx context.Context, claim passiveDiscoveryV3Claim) error {
	query := fmt.Sprintf(`SELECT ordinal,event_id,event_content_sha256 FROM passive_discovery_events_v3 FINAL
WHERE sensor_id=%s AND batch_id=%s ORDER BY ordinal LIMIT %d
SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`, chQuote(claim.Sensor), chQuote(claim.ID), claim.Count+1)
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return err
	}
	var rows []passiveDiscoveryV3HashRow
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return err
	}
	hash, err := passiveDiscoveryV3ManifestHash(rows, claim.Count)
	if err != nil {
		return err
	}
	if hash != claim.Hash {
		return fmt.Errorf("discovery input v3 selection hash mismatch for %s", claim.ID)
	}
	result, err := s.pg.db.ExecContext(ctx, `UPDATE passive_discovery_batch_progress SET verified_at=coalesce(verified_at,now()),last_error='',updated_at=now()
WHERE batch_id=$1 AND lease_owner=$2 AND processed_offset=$3 AND lease_until>now()`, claim.ID, claim.Owner, claim.Offset)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return fmt.Errorf("discovery input v3 verification lease lost: %v", err)
	}
	return nil
}

func (s *DBStore) readPassiveDiscoveryV3(ctx context.Context, claim passiveDiscoveryV3Claim, limit int) ([]normalized.Event, int, error) {
	if limit <= 0 || limit > passiveDiscoveryMaxBatch {
		limit = passiveDiscoveryMaxBatch
	}
	query := fmt.Sprintf(`SELECT ordinal,event_content_sha256,event_json
FROM passive_discovery_events_v3 FINAL WHERE sensor_id=%s AND batch_id=%s AND ordinal>=%d ORDER BY ordinal LIMIT %d
SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`, chQuote(claim.Sensor), chQuote(claim.ID), claim.Offset, limit)
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return nil, claim.Offset, err
	}
	raw, err = boundedPassiveDiscoveryRows(raw, passiveDiscoveryBatchBytes)
	if err != nil {
		return nil, claim.Offset, err
	}
	var rows []passiveDiscoveryV3Row
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return nil, claim.Offset, err
	}
	if len(rows) == 0 {
		return nil, claim.Offset, fmt.Errorf("discovery input v3 missing at batch %s offset %d", claim.ID, claim.Offset)
	}
	events := make([]normalized.Event, 0, len(rows))
	for i, row := range rows {
		if row.Ordinal != claim.Offset+i || row.Ordinal >= claim.Count || len(row.Hash) != 64 {
			return nil, claim.Offset, fmt.Errorf("discovery input v3 gap at batch %s offset %d", claim.ID, claim.Offset+i)
		}
		hash := sha256.Sum256([]byte(row.Document))
		if hex.EncodeToString(hash[:]) != row.Hash {
			return nil, claim.Offset, fmt.Errorf("discovery input v3 content hash mismatch at batch %s offset %d", claim.ID, row.Ordinal)
		}
		var event normalized.Event
		if err = json.Unmarshal([]byte(row.Document), &event); err != nil {
			return nil, claim.Offset, err
		}
		canonical, encodeErr := json.Marshal(event)
		if encodeErr != nil {
			return nil, claim.Offset, encodeErr
		}
		canonicalHash := sha256.Sum256(canonical)
		if hex.EncodeToString(canonicalHash[:]) != row.Hash {
			return nil, claim.Offset, fmt.Errorf("discovery input v3 canonical hash mismatch at batch %s offset %d", claim.ID, row.Ordinal)
		}
		events = append(events, event)
	}
	return events, claim.Offset + len(events), nil
}

func passiveDiscoveryArchiveHasHeadroom() error {
	path := os.Getenv("PROXY_SENTINEL_DISCOVERY_ARCHIVE_PATH")
	if path == "" {
		path = "/opt/proxy-sentinel"
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return err
	}
	if fs.Blocks == 0 || float64(fs.Bavail)/float64(fs.Blocks) < 0.20 {
		return fmt.Errorf("discovery archive paused: disk headroom below 20 percent")
	}
	return nil
}

func (s *DBStore) archivePassiveDiscoveryV3(ctx context.Context, claim passiveDiscoveryV3Claim) error {
	if err := passiveDiscoveryArchiveHasHeadroom(); err != nil {
		return err
	}
	all := make([]normalized.Event, 0, claim.Count)
	read := claim
	read.Offset = 0
	for read.Offset < read.Count {
		part, next, err := s.readPassiveDiscoveryV3(ctx, read, passiveDiscoveryMaxBatch)
		if err != nil {
			return err
		}
		all = append(all, part...)
		read.Offset = next
	}
	if len(all) != claim.Count {
		return fmt.Errorf("discovery archive input count mismatch: batch %s", claim.ID)
	}
	if err := s.ch.WriteDiscoveryEvidenceArchive(ctx, claim.ID, claim.Accepted, all); err != nil {
		return err
	}
	result, err := s.pg.db.ExecContext(ctx, `UPDATE passive_discovery_batch_progress SET archive_verified_at=coalesce(archive_verified_at,now()),updated_at=now()
WHERE batch_id=$1 AND lease_owner=$2 AND processed_offset=$3 AND lease_until>now()`, claim.ID, claim.Owner, claim.Offset)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return fmt.Errorf("discovery archive verification lease lost: %v", err)
	}
	return nil
}

func (s *DBStore) failPassiveDiscoveryV3(ctx context.Context, claim passiveDiscoveryV3Claim, cause error) {
	report, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_, _ = s.pg.db.ExecContext(report, `UPDATE passive_discovery_batch_progress SET attempts=attempts+1,last_error=$3,
next_attempt_at=now()+least(interval '60 seconds',interval '1 second'*power(2,least(attempts,5))),
lease_owner='',lease_until='-infinity',updated_at=now()
WHERE batch_id=$1 AND lease_owner=$2 AND completed_at IS NULL`, claim.ID, claim.Owner, cause.Error())
}

func (s *DBStore) processPassiveDiscoveryV3Once(ctx context.Context, sensor string, scope passiveDiscoveryScope, shadow bool) (bool, int, error) {
	claim, found, err := s.claimPassiveDiscoveryV3(ctx, sensor, shadow)
	if err != nil || !found {
		return found, 0, err
	}
	if claim.Sensor != sensor {
		err = fmt.Errorf("discovery input v3 sensor mismatch: %s", claim.Sensor)
		s.failPassiveDiscoveryV3(ctx, claim, err)
		return true, 0, err
	}
	if !claim.Verified {
		if err = s.verifyPassiveDiscoveryV3(ctx, claim); err != nil {
			s.failPassiveDiscoveryV3(ctx, claim, err)
			return true, 0, err
		}
	}
	if !claim.ArchiveVerified {
		if err = s.archivePassiveDiscoveryV3(ctx, claim); err != nil {
			s.failPassiveDiscoveryV3(ctx, claim, err)
			return true, 0, err
		}
	}
	if shadow {
		_, err = s.pg.db.ExecContext(ctx, `UPDATE passive_discovery_batch_progress SET lease_owner='',lease_until='-infinity',updated_at=now() WHERE batch_id=$1 AND lease_owner=$2`, claim.ID, claim.Owner)
		return true, 0, err
	}
	events, end, err := s.readPassiveDiscoveryV3(ctx, claim, passiveDiscoveryBatchSize)
	if err != nil {
		s.failPassiveDiscoveryV3(ctx, claim, err)
		return true, 0, err
	}
	passiveBatchMu.Lock()
	stats, err := s.processPassiveDiscoveryBatchWithProgress(ctx, events, scope, func(ctx context.Context, tx *sql.Tx, stats passiveDiscoveryBatchStats) error {
		protocols, _ := json.Marshal(stats.Protocols)
		reasons, _ := json.Marshal(stats.Reasons)
		if _, updateErr := tx.ExecContext(ctx, `INSERT INTO passive_discovery_state(sensor_id,processed_events,emitted_observations,skipped_events,protocol_counts,skip_counts,last_success_at)
 VALUES($1,$2,$3,$4,$5,$6,now()) ON CONFLICT(sensor_id) DO UPDATE SET
 processed_events=passive_discovery_state.processed_events+EXCLUDED.processed_events,
 emitted_observations=passive_discovery_state.emitted_observations+EXCLUDED.emitted_observations,
 skipped_events=passive_discovery_state.skipped_events+EXCLUDED.skipped_events,
 protocol_counts=coalesce((SELECT jsonb_object_agg(key,total) FROM (SELECT key,sum(value::bigint) total FROM (SELECT * FROM jsonb_each_text(passive_discovery_state.protocol_counts) UNION ALL SELECT * FROM jsonb_each_text(EXCLUDED.protocol_counts)) counts GROUP BY key) totals),'{}'::jsonb),
 skip_counts=coalesce((SELECT jsonb_object_agg(key,total) FROM (SELECT key,sum(value::bigint) total FROM (SELECT * FROM jsonb_each_text(passive_discovery_state.skip_counts) UNION ALL SELECT * FROM jsonb_each_text(EXCLUDED.skip_counts)) counts GROUP BY key) totals),'{}'::jsonb),
 last_success_at=now(),last_error='',updated_at=now()`, sensor, stats.Processed, stats.Emitted, stats.Skipped, protocols, reasons); updateErr != nil {
			return updateErr
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE passive_discovery_batch_progress SET processed_offset=$3,
 completed_at=CASE WHEN $3=selected_count THEN now() ELSE NULL END,
 lease_owner='',lease_until='-infinity',last_error='',next_attempt_at=now(),updated_at=now()
 WHERE batch_id=$1 AND lease_owner=$2 AND processed_offset=$4 AND lease_until>now()`, claim.ID, claim.Owner, end, claim.Offset)
		if updateErr != nil {
			return updateErr
		}
		updated, updateErr := result.RowsAffected()
		if updateErr != nil || updated != 1 {
			return fmt.Errorf("discovery input v3 progress lease lost: %v", updateErr)
		}
		return nil
	})
	passiveBatchMu.Unlock()
	if err != nil {
		s.failPassiveDiscoveryV3(ctx, claim, err)
		return true, 0, err
	}
	return true, stats.Processed, nil
}

func (s *DBStore) runPassiveDiscoveryV3(ctx context.Context, sensor string, shadow bool) {
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 45*time.Second)
		scope, err := parsePassiveDiscoveryScope(os.Getenv("PROXY_SENTINEL_DISCOVERY_CIDRS"))
		found, processed := false, 0
		if err == nil {
			found, processed, err = s.processPassiveDiscoveryV3Once(work, sensor, scope, shadow)
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "passive discovery v3 batch failed: shadow=%t processed=%d error=%v\n", shadow, processed, err)
		}
		delay := time.Second
		if found && err == nil {
			delay = 0
		} else if !found {
			delay = 5 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
