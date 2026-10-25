package discovery

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var ErrDiscoveryLeaseLost = errors.New("discovery lease lost")
var ErrDiscoveryContentConflict = errors.New("discovery content conflict")

type discoveryClaim struct {
	ID, Token, Source string
	Raw               []byte
	Offset            int
	Archived          bool
	Accepted          time.Time
	Segmented         bool
	Total             int
	SegmentFirst      int
	SegmentCount      int
	SegmentHash       string
	SegmentArchived   bool
}

func (r Repository) claimDiscovery(ctx context.Context, lane string) (discoveryClaim, error) {
	var c discoveryClaim
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return c, err
	}
	c.Token = hex.EncodeToString(token[:])
	// Short atomic claim. Remote I/O starts only after this statement commits.
	var selected sql.NullInt64
	err := r.DB.QueryRowContext(ctx, `UPDATE discovery_batch_work w SET lease_token=$2,lease_until=now()+interval '30 seconds'
 FROM (SELECT q.batch_id,b.started_at,b.source_kind FROM discovery_batch_work q JOIN ingest_batches b USING(batch_id)
 WHERE q.lane=$1 AND ($3='' OR b.sensor_id=$3) AND NOT q.completed AND q.next_attempt_at<=now() AND q.lease_until<=now()
 AND (b.source_kind='discovery-v2' OR b.status='committed') ORDER BY q.next_attempt_at,q.created_at FOR UPDATE OF q SKIP LOCKED LIMIT 1) selected
 WHERE w.batch_id=selected.batch_id RETURNING w.batch_id,CASE WHEN w.selected_event_count IS NULL THEN w.events ELSE NULL END,w.processed_offset,w.archived,selected.started_at,selected.source_kind,w.selected_event_count`, lane, c.Token, r.ClaimSensor).Scan(&c.ID, &c.Raw, &c.Offset, &c.Archived, &c.Accepted, &c.Source, &selected)
	if err != nil || !selected.Valid {
		return c, err
	}
	c.Segmented, c.Total = true, int(selected.Int64)
	var count, size int
	err = r.DB.QueryRowContext(ctx, `SELECT first_offset,event_count,byte_count,content_sha256,events,archive_verified_at IS NOT NULL
 FROM discovery_batch_segments WHERE batch_id=$1 AND first_offset<=$2 AND first_offset+event_count>$2 AND released_at IS NULL`, c.ID, c.Offset).Scan(&c.SegmentFirst, &count, &size, &c.SegmentHash, &c.Raw, &c.SegmentArchived)
	if err == nil {
		if count < 1 || count > DiscoverySegmentMaxEvents || size < 2 || size > DiscoverySegmentMaxBytes || len(c.Raw) > DiscoverySegmentMaxBytes*2 || c.SegmentFirst+count > c.Total || c.Offset < c.SegmentFirst || c.Offset >= c.SegmentFirst+count {
			err = fmt.Errorf("discovery segment integrity mismatch")
		} else {
			c.SegmentCount = count
		}
	}
	if err != nil {
		r.failDiscovery(ctx, c, "claim_segment", err)
	}
	return c, err
}

func (r Repository) markDiscoverySegmentArchived(ctx context.Context, c discoveryClaim) error {
	result, err := r.DB.ExecContext(ctx, `UPDATE discovery_batch_segments s SET archive_verified_at=coalesce(s.archive_verified_at,now())
 FROM discovery_batch_work w WHERE s.batch_id=$1 AND s.first_offset=$2 AND s.released_at IS NULL
 AND w.batch_id=s.batch_id AND w.lease_token=$3 AND w.processed_offset=$4 AND w.lease_until>now()`, c.ID, c.SegmentFirst, c.Token, c.Offset)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrDiscoveryLeaseLost
	}
	return nil
}
func (r Repository) beginDiscoveryPublish(ctx context.Context, c discoveryClaim) (*sql.Tx, error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT lease_token=$2 AND processed_offset=$3 AND lease_until>now() AND NOT completed FROM discovery_batch_work WHERE batch_id=$1 FOR UPDATE`, c.ID, c.Token, c.Offset).Scan(&valid)
	if err != nil || !valid {
		_ = tx.Rollback()
		if err != nil {
			return nil, err
		}
		return nil, ErrDiscoveryLeaseLost
	}
	return tx, nil
}
func (r Repository) failDiscovery(ctx context.Context, c discoveryClaim, stage string, cause error) {
	report, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	// A stale worker cannot clear a replacement worker's lease or error state.
	_, _ = r.DB.ExecContext(report, `UPDATE discovery_batch_work SET attempts=attempts+1,error=$3,error_stage=$4,last_failure_at=now(),lease_token='',lease_until='-infinity',next_attempt_at=now()+least(interval '60 seconds',interval '1 second'*power(2,least(attempts,5))) WHERE batch_id=$1 AND lease_token=$2 AND NOT completed`, c.ID, c.Token, WorkErrorCode(cause), stage)
}
