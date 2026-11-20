package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/streamlog"
)

type SharedPacketRepairResult struct {
	Examined int  `json:"examined"`
	Complete bool `json:"complete"`
	Paused   bool `json:"paused_for_realtime"`
}

type sharedPacketRepairCursor struct {
	At        time.Time
	Key, Hash string
}

// RepairSharedPacketPage processes one bounded page of the immutable interval
// preceding the audited binding change. Each event has its own durable receipt;
// a crash before advancing the scan cursor only repeats verification.
func (q StreamSharedJobQueue) RepairSharedPacketPage(ctx context.Context, ch *ClickHouseStore, sensor, scope, path, epoch string, freshness time.Duration) (SharedPacketRepairResult, error) {
	var result SharedPacketRepairResult
	if q.DB == nil || ch == nil || sensor == "" || scope == "" || path == "" || epoch == "" || freshness <= 0 {
		return result, errors.New("invalid shared packet repair source")
	}
	var from, through time.Time
	var initialFile string
	var initialOffset int64
	err := q.DB.QueryRowContext(ctx, `SELECT f.legacy_cutoff_at,d.recorded_at,f.file_id,f.start_offset FROM stream_shared_source_cutovers s
 JOIN stream_source_cutovers f USING(epoch,source_kind,source_path)
 JOIN stream_discard_manifest d ON d.source_kind=s.source_kind AND d.source_path=s.source_path
 AND d.legacy_kind='shared_binding_reconciled' AND d.legacy_reference=s.epoch AND d.content_sha256=s.canceled_manifest_sha256
 WHERE s.sensor_id=$1 AND s.scope_id=$2 AND s.source_path=$3 AND s.epoch=$4 AND s.source_owner='packet-sidecar'
 AND s.state='active' AND f.state='active'`, sensor, scope, path, epoch).Scan(&from, &through, &initialFile, &initialOffset)
	if err != nil {
		return result, fmt.Errorf("load audited packet repair interval: %w", err)
	}
	var cursor sharedPacketRepairCursor
	err = q.DB.QueryRowContext(ctx, `SELECT indexed_at,event_key,content_sha256,complete FROM stream_shared_packet_repair_progress WHERE epoch=$1`, epoch).Scan(&cursor.At, &cursor.Key, &cursor.Hash, &result.Complete)
	if errors.Is(err, sql.ErrNoRows) {
		cursor.At = from
	} else if err != nil || result.Complete {
		return result, err
	}
	err = q.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shared_observation_jobs WHERE sensor_id=$1
 AND revision>completed_revision AND NOT expired AND canceled_epoch='' AND dirty_since<now()-$2::bigint*interval '1 second')`, sensor, int64(freshness.Seconds())).Scan(&result.Paused)
	if err != nil || result.Paused {
		return result, err
	}
	refs, err := ch.listSharedPacketRepairRefs(ctx, sensor, scope, epoch, from, through, cursor)
	if err != nil {
		return result, err
	}
	for _, ref := range refs {
		if err = q.repairSharedPacketEvent(ctx, ch, sensor, scope, path, epoch, initialFile, initialOffset, from, through, freshness, ref); err != nil {
			return result, err
		}
		cursor = sharedPacketRepairCursor{At: ref.IndexedAt, Key: ref.Body.Key, Hash: ref.Body.SHA256}
		result.Examined++
	}
	result.Complete = len(refs) < sharedPacketRepairPageSize
	_, err = q.DB.ExecContext(ctx, `INSERT INTO stream_shared_packet_repair_progress(epoch,indexed_at,event_key,content_sha256,complete)
 VALUES($1,$2,$3,$4,$5) ON CONFLICT(epoch) DO UPDATE SET indexed_at=EXCLUDED.indexed_at,event_key=EXCLUDED.event_key,
 content_sha256=EXCLUDED.content_sha256,complete=EXCLUDED.complete
 WHERE NOT stream_shared_packet_repair_progress.complete AND
 (stream_shared_packet_repair_progress.indexed_at,stream_shared_packet_repair_progress.event_key,stream_shared_packet_repair_progress.content_sha256)
 <= (EXCLUDED.indexed_at,EXCLUDED.event_key,EXCLUDED.content_sha256)`, epoch, cursor.At, cursor.Key, cursor.Hash, result.Complete)
	return result, err
}

const sharedPacketRepairPageSize = 16

func (s *ClickHouseStore) listSharedPacketRepairRefs(ctx context.Context, sensor, scope, epoch string, from, through time.Time, cursor sharedPacketRepairCursor) ([]StreamSharedSignalRef, error) {
	stamp := func(at time.Time) string {
		return "parseDateTime64BestEffort(" + chQuote(at.UTC().Format(time.RFC3339Nano)) + ",6)"
	}
	query := fmt.Sprintf(`SELECT DISTINCT indexed_at,event_key,content_sha256,body_ref FROM stream_event_search
 PREWHERE scope_id=%s AND protocol IN ('ieee1905_client_association','ieee1905_client_snapshot','capture_coverage')
 WHERE sensor_id=%s AND source='packet-sidecar' AND startsWith(event_key,%s) AND indexed_at>=%s AND indexed_at<=%s
 AND (indexed_at,event_key,content_sha256)>(%s,%s,%s)
 ORDER BY indexed_at,event_key,content_sha256 LIMIT %d
 SETTINGS max_threads=1,max_memory_usage=134217728,max_rows_to_read=2000000,max_execution_time=5 FORMAT JSONEachRow`,
		chQuote(scope), chQuote(sensor), chQuote(epoch+":"), stamp(from), stamp(through), stamp(cursor.At), chQuote(cursor.Key), chQuote(cursor.Hash), sharedPacketRepairPageSize)
	raw, err := s.query(ctx, query)
	if err != nil {
		return nil, err
	}
	var refs []StreamSharedSignalRef
	if len(bytes.TrimSpace(raw)) == 0 {
		return refs, nil
	}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var row struct {
			At   string `json:"indexed_at"`
			Key  string `json:"event_key"`
			Hash string `json:"content_sha256"`
			Ref  string `json:"body_ref"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, err
		}
		at, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.At))
		if err != nil {
			return nil, err
		}
		body, err := ParseStreamBodyRef(row.Ref)
		if err != nil || body.Scope != scope || body.Key != row.Key || body.SHA256 != row.Hash || !strings.HasPrefix(body.Key, epoch+":") || at.Before(from.Truncate(time.Microsecond)) || at.After(through) {
			return nil, streamlog.ErrContentConflict
		}
		refs = append(refs, StreamSharedSignalRef{IndexedAt: at, Body: body})
	}
	return refs, nil
}

func (q StreamSharedJobQueue) repairSharedPacketEvent(ctx context.Context, ch *ClickHouseStore, sensor, scope, path, epoch, initialFile string, initialOffset int64, from, through time.Time, freshness time.Duration, locator StreamSharedSignalRef) error {
	ref := locator.Body
	var prior string
	err := q.DB.QueryRowContext(ctx, `SELECT content_sha256 FROM stream_shared_packet_repairs WHERE epoch=$1 AND event_key=$2`, epoch, ref.Key).Scan(&prior)
	if err == nil {
		if prior != ref.SHA256 {
			return streamlog.ErrContentConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	event, found, err := ch.GetStreamEventByRef(ctx, ref)
	if err != nil {
		return err
	}
	if !found || !sharedPacketEvent(event) || ref.Key != epoch+":"+event.EventID || stringFromMap(event.Observer, "sensor_id") != sensor || streamScope(event) != scope {
		return streamlog.ErrContentConflict
	}
	observed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return err
	}
	segment, err := ch.readSharedPacketArchivePosition(ctx, ref, path, epoch)
	if err != nil {
		return err
	}
	if segment.AcceptedAt.Before(from.Truncate(time.Microsecond)) || segment.AcceptedAt.After(through) || (segment.FileID == initialFile && segment.StartOffset < initialOffset) {
		return streamlog.ErrContentConflict
	}
	segmentID := streamlog.SourceSegmentID(segment)
	if strings.HasPrefix(event.EventID, "stream4-") && !strings.HasPrefix(event.EventID, "stream4-"+segmentID+"-") {
		return streamlog.ErrContentConflict
	}
	segment.Events = append(segment.Events, event)
	p, err := prepareStreamSharedJobs(segment)
	if err != nil {
		return err
	}
	tx, err := q.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	generation, err := lockSharedStreamBinding(ctx, tx, epoch, path, p, true)
	if err != nil {
		return err
	}
	if err := lockSharedPacketSegment(ctx, tx, segmentID); err != nil {
		return err
	}
	var normalReceipt bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM stream_shared_segment_receipts WHERE segment_id=$1 AND epoch=$2)`, segmentID, epoch).Scan(&normalReceipt); err != nil {
		return err
	}
	state := "enqueued"
	if normalReceipt {
		state = "already_enqueued"
	} else if !time.Now().Before(observed.Add(freshness)) {
		state = "expired_without_evaluation"
	}
	claim, err := tx.ExecContext(ctx, `INSERT INTO stream_shared_packet_repairs(epoch,event_key,content_sha256,accepted_at,observed_at,state)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, epoch, ref.Key, ref.SHA256, segment.AcceptedAt, observed, state)
	if err != nil {
		return err
	}
	inserted, err := claim.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		if err := tx.QueryRowContext(ctx, `SELECT content_sha256 FROM stream_shared_packet_repairs WHERE epoch=$1 AND event_key=$2`, epoch, ref.Key).Scan(&prior); err != nil {
			return err
		}
		if prior != ref.SHA256 {
			return streamlog.ErrContentConflict
		}
	} else if state == "enqueued" {
		if err := enqueuePreparedSharedJobs(ctx, tx, p, generation, epoch, segment.AcceptedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *ClickHouseStore) readSharedPacketArchivePosition(ctx context.Context, ref StreamBodyRef, path, epoch string) (streamlog.Segment, error) {
	query := fmt.Sprintf(`SELECT DISTINCT accepted_at,source_path,file_id,start_offset,end_offset,parser_version,raw_sha256 FROM %s
 PREWHERE archive_month=%s AND scope_id=%s AND event_key=%s AND content_sha256=%s
 LIMIT 2 SETTINGS max_threads=1,max_execution_time=5 FORMAT JSONEachRow`, streamBodyTable(ref.Class, ref.BodyLayout), ref.Month, chQuote(ref.Scope), chQuote(ref.Key), chQuote(ref.SHA256))
	raw, err := s.query(ctx, query)
	if err != nil {
		return streamlog.Segment{}, err
	}
	var row struct {
		Accepted string `json:"accepted_at"`
		Path     string `json:"source_path"`
		File     string `json:"file_id"`
		Start    int64  `json:"start_offset"`
		End      int64  `json:"end_offset"`
		Parser   string `json:"parser_version"`
		RawHash  string `json:"raw_sha256"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &row); err != nil {
		return streamlog.Segment{}, fmt.Errorf("unique packet archive position: %w", errors.Join(streamlog.ErrContentConflict, err))
	}
	at, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.Accepted))
	if err != nil || row.Path != path || !strings.HasPrefix(row.File, path+":") || row.Start < 0 || row.End <= row.Start || row.Parser != "device-v1" || len(row.RawHash) != 64 {
		return streamlog.Segment{}, streamlog.ErrContentConflict
	}
	return streamlog.Segment{Epoch: epoch, Source: "device-signals", SourcePath: path, FileID: row.File,
		StartOffset: row.Start, EndOffset: row.End, ParserVersion: row.Parser, RawSHA256: row.RawHash, AcceptedAt: at}, nil
}
