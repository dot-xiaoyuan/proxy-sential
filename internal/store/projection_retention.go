package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// projectionHotRetention is the hot window for ended snapshot members (AGENTS.md: identity and
	// address history is hot for 30 days and archived to one year after first ingest).
	projectionHotRetention = 30 * 24 * time.Hour
	// projectionArchiveBatch bounds one archive-and-delete step.
	projectionArchiveBatch = 1000
	// projectionRetentionPass bounds the steps of one pass; the inflow is about 100k ended members a day.
	projectionRetentionPass = 20
	projectionRetentionIdle = 10 * time.Minute
)

// projectionArchiveRow is one ended projection member as archived.
type projectionArchiveRow struct {
	Source       string          `json:"source"`
	SensorID     string          `json:"sensor_id"`
	CampusID     string          `json:"campus_id"`
	AccessDomain string          `json:"access_domain"`
	SessionID    string          `json:"session_id"`
	IP           string          `json:"ip"`
	AccountID    string          `json:"account_id"`
	ConfirmedAt  time.Time       `json:"confirmed_at"`
	Document     json.RawMessage `json:"document"`
}

// Case-referenced IPs keep their history; a case without an IP keeps everything (fail closed), the
// same rule as device retention.
const projectionRetentionProtected = `NOT EXISTS (SELECT 1 FROM protected_ips c WHERE c.ip IS NULL) AND NOT EXISTS (SELECT 1 FROM protected_ips c WHERE host(c.ip)=p.ip)`

// projectionRetentionCandidatesSQL reads the oldest expired ended members in confirmed_at order, which
// the change-cursor index serves without a sort.
const projectionRetentionCandidatesSQL = deviceRetentionReferences + ` SELECT p.source,p.sensor_id,p.campus_id,p.access_domain,p.session_id,p.ip,p.account_id,p.confirmed_at,p.document
FROM account_identity_session_projection p
WHERE p.confirmed_at<$1 AND COALESCE(p.document->>'ended_at','')<>'' AND ` + projectionRetentionProtected + `
ORDER BY p.confirmed_at LIMIT $2`

// projectionRetentionDeleteSQL deletes exactly the archived versions: a row that changed, reopened or
// became case-protected since it was read stays.
const projectionRetentionDeleteSQL = deviceRetentionReferences + ` DELETE FROM account_identity_session_projection p
USING jsonb_to_recordset($1::jsonb) r(source text,sensor_id text,campus_id text,access_domain text,session_id text,ip text,confirmed_at timestamptz)
WHERE p.source=r.source AND p.sensor_id=r.sensor_id AND p.campus_id=r.campus_id AND p.access_domain=r.access_domain AND p.session_id=r.session_id AND p.ip=r.ip
 AND p.confirmed_at=r.confirmed_at AND COALESCE(p.document->>'ended_at','')<>'' AND ` + projectionRetentionProtected

// WriteIdentityProjectionArchive stores a batch and verifies every ordinal and content hash; a replay
// of a complete batch writes nothing.
func (s *ClickHouseStore) WriteIdentityProjectionArchive(ctx context.Context, batch string, rows []projectionArchiveRow) error {
	if len(rows) > projectionArchiveBatch {
		return fmt.Errorf("projection archive batch budget exceeded")
	}
	hashes := make([]string, len(rows))
	for i, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(encoded)
		hashes[i] = hex.EncodeToString(sum[:])
	}
	read := func() (map[int]bool, error) {
		raw, err := s.query(ctx, `SELECT ordinal,content_hash FROM identity_projection_history_archive WHERE batch_id=`+chQuote(batch)+` GROUP BY ordinal,content_hash LIMIT `+fmt.Sprint(len(rows)+1)+` SETTINGS max_threads=1,max_execution_time=10 FORMAT JSONEachRow`)
		if err != nil {
			return nil, err
		}
		var stored []struct {
			Ordinal int    `json:"ordinal"`
			Hash    string `json:"content_hash"`
		}
		if err = decodeJSONEachRow(raw, &stored); err != nil {
			return nil, err
		}
		found := map[int]bool{}
		for _, row := range stored {
			if row.Ordinal < 0 || row.Ordinal >= len(rows) || row.Hash != hashes[row.Ordinal] {
				return nil, fmt.Errorf("projection archive batch content conflict")
			}
			found[row.Ordinal] = true
		}
		return found, nil
	}
	found, err := read()
	if err != nil {
		return err
	}
	if len(found) == len(rows) {
		return nil
	}
	var buffer bytes.Buffer
	buffer.WriteString("INSERT INTO identity_projection_history_archive FORMAT JSONEachRow\n")
	encoder := json.NewEncoder(&buffer)
	for i, row := range rows {
		if found[i] {
			continue
		}
		if err = encoder.Encode(map[string]any{
			"batch_id": batch, "ordinal": i, "source": row.Source, "sensor_id": row.SensorID, "campus_id": row.CampusID,
			"access_domain": row.AccessDomain, "session_id": row.SessionID, "ip": row.IP, "account_id": row.AccountID,
			"confirmed_at": row.ConfirmedAt.UTC().Format("2006-01-02 15:04:05.000000"), "content_hash": hashes[i], "document": string(row.Document),
		}); err != nil {
			return err
		}
	}
	if err = s.exec(ctx, buffer.String()); err != nil {
		return err
	}
	if found, err = read(); err != nil {
		return err
	}
	if len(found) != len(rows) {
		return fmt.Errorf("projection archive incomplete: %d of %d rows verified", len(found), len(rows))
	}
	return nil
}

// archiveEndedProjectionBatch archives one batch of expired ended members, then deletes exactly those
// versions. Nothing is deleted unless the archive verified the whole batch.
func (s *DBStore) archiveEndedProjectionBatch(ctx context.Context, now time.Time) (int, error) {
	result, err := s.pg.db.QueryContext(ctx, projectionRetentionCandidatesSQL, now.Add(-projectionHotRetention), projectionArchiveBatch)
	if err != nil {
		return 0, err
	}
	var rows []projectionArchiveRow
	for result.Next() {
		var row projectionArchiveRow
		var document []byte
		if err = result.Scan(&row.Source, &row.SensorID, &row.CampusID, &row.AccessDomain, &row.SessionID, &row.IP, &row.AccountID, &row.ConfirmedAt, &document); err != nil {
			result.Close()
			return 0, err
		}
		row.Document = document
		rows = append(rows, row)
	}
	err = result.Err()
	result.Close()
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	// The batch id follows the exact versions, so a retry after a crash finds the same archive batch.
	keys := make([]string, len(rows))
	for i, row := range rows {
		keys[i] = strings.Join([]string{row.Source, row.SensorID, row.CampusID, row.AccessDomain, row.SessionID, row.IP, row.ConfirmedAt.UTC().Format(time.RFC3339Nano)}, "\x1f")
	}
	sum := sha256.Sum256([]byte(strings.Join(keys, "\x1e")))
	batch := "projection-" + hex.EncodeToString(sum[:])
	if err = s.ch.WriteIdentityProjectionArchive(ctx, batch, rows); err != nil {
		return 0, fmt.Errorf("archive ended projection members: %w", err)
	}
	body, err := json.Marshal(rows)
	if err != nil {
		return 0, err
	}
	deleted, err := s.pg.db.ExecContext(ctx, projectionRetentionDeleteSQL, body)
	if err != nil {
		return 0, err
	}
	n, _ := deleted.RowsAffected()
	return int(n), nil
}

// runProjectionRetention drains expired ended members in bounded passes and idles when none are due.
func (s *DBStore) runProjectionRetention(ctx context.Context) {
	for ctx.Err() == nil {
		drained := false
		for step := 0; step < projectionRetentionPass && ctx.Err() == nil; step++ {
			work, cancel := context.WithTimeout(ctx, 2*time.Minute)
			n, err := s.archiveEndedProjectionBatch(work, time.Now().UTC())
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					fmt.Fprintf(os.Stderr, "projection retention: %v\n", err)
				}
				break
			}
			if n < projectionArchiveBatch {
				drained = true
				break
			}
		}
		delay := time.Minute
		if drained {
			delay = projectionRetentionIdle
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}
