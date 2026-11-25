package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const passiveArchiveBatchBytes = 16 << 20

type passiveArchiveSource struct {
	Path, FileID, Digest string
	Start, End           int64
	Accepted             time.Time
}

func passiveRawDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *DBStore) archivePassiveBatch(ctx context.Context, roots []string) (bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var batch string
	err = tx.QueryRowContext(ctx, `SELECT batch_id FROM passive_archive_rows WHERE verified_at IS NULL AND attempts<8 AND next_attempt<=now()
 ORDER BY next_attempt,batch_id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&batch)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var locked bool
	if err = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1,2))", batch).Scan(&locked); err != nil || !locked {
		return false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT row_hash,batch_hash FROM passive_archive_rows WHERE batch_id=$1 AND verified_at IS NULL AND attempts<8 AND next_attempt<=now() ORDER BY row_hash LIMIT 64 FOR UPDATE SKIP LOCKED`, batch)
	if err != nil {
		return true, err
	}
	hashes := map[string]string{}
	for rows.Next() {
		var h, b string
		if err := rows.Scan(&h, &b); err != nil {
			rows.Close()
			return true, err
		}
		hashes[h] = b
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return true, err
	}
	rows.Close()
	if len(hashes) == 0 {
		return false, nil
	}
	var src passiveArchiveSource
	err = tx.QueryRowContext(ctx, `SELECT source_path,file_id,start_offset,end_offset,checksum,committed_at FROM ingest_batches WHERE batch_id=$1 AND status='committed' AND committed_at IS NOT NULL`, batch).Scan(&src.Path, &src.FileID, &src.Start, &src.End, &src.Digest, &src.Accepted)
	if errors.Is(err, sql.ErrNoRows) {
		err = errors.New("no committed ingest ledger entry for this batch")
	} else if err != nil {
		return true, err
	}
	var verified map[string]bool
	if err == nil {
		verified, err = s.verifyPassiveArchive(ctx, batch, src, roots, hashes)
	}
	var good, bad []string
	for h := range hashes {
		if verified[h] {
			good = append(good, h)
		} else {
			bad = append(bad, h)
		}
	}
	if len(good) > 0 {
		if _, e := tx.ExecContext(ctx, `UPDATE passive_archive_rows SET accepted_at=$3,verified_at=now(),last_error='' WHERE batch_id=$1 AND row_hash=ANY($2::text[])`, batch, good, src.Accepted); e != nil {
			return true, e
		}
	}
	if len(bad) > 0 {
		reason := "record not found in verified source batch"
		if err != nil {
			reason = err.Error()
			if len(reason) > 512 {
				reason = reason[:512]
			}
		}
		if _, e := tx.ExecContext(ctx, `UPDATE passive_archive_rows SET attempts=attempts+1,next_attempt=now()+ interval '1 minute'*(1<<least(attempts,7)),last_error=$3 WHERE batch_id=$1 AND row_hash=ANY($2::text[])`, batch, bad, reason); e != nil {
			return true, e
		}
	}
	return true, tx.Commit()
}

// Re-read and hash the stored original bytes before acknowledging a receipt.
// A crash after the insert resumes by verifying the existing archive first.
func (s *DBStore) verifyPassiveArchive(ctx context.Context, batch string, src passiveArchiveSource, roots []string, hashes map[string]string) (map[string]bool, error) {
	wanted := map[string]bool{}
	var keys []string
	for h, b := range hashes {
		if b == src.Digest {
			wanted[h] = true
			keys = append(keys, chQuote(h))
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("ledger digest disagrees with evidence")
	}
	at := src.Accepted.UTC().Format("2006-01-02 15:04:05.000000")
	read := func() (map[string]bool, error) {
		raw, e := s.ch.query(ctx, `SELECT row_hash,min(batch_hash=`+chQuote(src.Digest)+` AND accepted_at=toDateTime64(`+chQuote(at)+`,6,'UTC') AND lower(hex(SHA256(base64Decode(raw_b64))))=row_hash) AS valid FROM passive_discovery_raw_archive WHERE batch_id=`+chQuote(batch)+` AND row_hash IN (`+strings.Join(keys, ",")+`) GROUP BY row_hash SETTINGS max_threads=1,max_execution_time=5 FORMAT JSONEachRow`)
		if e != nil {
			return nil, e
		}
		var items []struct {
			Hash  string `json:"row_hash"`
			Valid int    `json:"valid"`
		}
		if e = decodeJSONEachRow(raw, &items); e != nil {
			return nil, e
		}
		known := map[string]bool{}
		for _, i := range items {
			if i.Valid != 1 {
				return nil, fmt.Errorf("archive content conflict")
			}
			known[i.Hash] = true
		}
		return known, nil
	}
	known, err := read()
	if err != nil || len(known) == len(wanted) {
		return known, err
	}
	found, err := readPassiveArchiveRows(ctx, src, roots, os.Getenv("PROXY_SENTINEL_PASSIVE_ARCHIVE_ROTATION_DIR"), wanted)
	if err != nil {
		return known, err
	}
	var buf bytes.Buffer
	buf.WriteString("INSERT INTO passive_discovery_raw_archive FORMAT JSONEachRow\n")
	enc := json.NewEncoder(&buf)
	inserts := 0
	for h, data := range found {
		if known[h] {
			continue
		}
		if err = enc.Encode(map[string]string{"batch_id": batch, "row_hash": h, "batch_hash": src.Digest, "accepted_at": at, "raw_b64": base64.StdEncoding.EncodeToString(data)}); err != nil {
			return known, err
		}
		inserts++
	}
	if inserts == 0 {
		return known, nil
	}
	if err = s.ch.exec(ctx, buf.String()); err != nil {
		return known, err
	}
	return read()
}

func (s *DBStore) runPassiveRawArchive(ctx context.Context) {
	roots := []string{"/opt/proxy-sentinel/data/zeek/logs", "/opt/proxy-sentinel/data/device-signals"}
	var nextAdopt time.Time
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		job, cancel := context.WithTimeout(ctx, 12*time.Second)
		did, err := s.archivePassiveBatch(job, roots)
		if err == nil && os.Getenv("PROXY_SENTINEL_PASSIVE_ARCHIVE_ADOPT") == "true" && time.Now().After(nextAdopt) {
			// Historical replay may only add work while the live queue is small.
			_, err = s.pg.db.ExecContext(job, `SELECT passive_archive_adopt(32) WHERE NOT EXISTS(SELECT 1 FROM passive_archive_rows WHERE verified_at IS NULL AND attempts=0 OFFSET 128 LIMIT 1)`)
			nextAdopt = time.Now().Add(15 * time.Second)
		}
		cancel()
		delay := time.Second
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("passive evidence archive: %v", err)
			delay = 5 * time.Second
		} else if did {
			delay = 100 * time.Millisecond
		}
		timer.Reset(delay)
	}
}
