package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

var errIdentityDeltaStaleSnapshot = errors.New("older snapshot retained for interval repair; current projection is newer")

var errIdentityDeltaOversize = errors.New("identity IP exceeds atomic batch limits")

const identityDeltaMaxBytes = 1 << 20
const identityDeltaMaxMembers = 500

type identityDeltaMember struct {
	Ordinal     int             `json:"ordinal"`
	Key         string          `json:"member_key"`
	SessionID   string          `json:"session_id"`
	IP          string          `json:"ip"`
	AccountID   string          `json:"account_id"`
	Fingerprint string          `json:"fingerprint"`
	Document    json.RawMessage `json:"document"`
	Kind        string          `json:"kind"`
}

func identityMemberFingerprint(s AccountSession) string {
	s.RawRef = nil
	s.LastConfirmedAt = ""
	s.StartedAt = ""
	raw, _ := json.Marshal(s)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	for _, k := range []string{"raw_ref", "last_confirmed_at", "started_at", "first_confirmed_at"} {
		delete(doc, k)
	}
	raw, _ = json.Marshal(doc)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Input is ordered by IP/member key. Never split responsibility for an IP.
func identityDeltaBatch(rows []identityDeltaMember, limit, byteLimit int) ([]identityDeltaMember, error) {
	n, bytes := 0, 0
	for n < len(rows) {
		end, cost := n, 0
		for end < len(rows) && rows[end].IP == rows[n].IP {
			cost += len(rows[end].Document) + len(rows[end].Key) + 128
			end++
		}
		if end-n > identityDeltaMaxMembers || cost > byteLimit {
			return nil, errIdentityDeltaOversize
		}
		if n > 0 && (end > limit || bytes+cost > byteLimit) {
			break
		}
		n = end
		bytes += cost
		if n >= limit {
			break
		}
	}
	return rows[:n], nil
}

type identityDeltaPressure struct {
	healthy int
	paused  bool
}

func (p *identityDeltaPressure) allow(age time.Duration, blocked bool) bool {
	if age > 5*time.Second || blocked {
		p.paused = true
		p.healthy = 0
		return false
	}
	if p.paused {
		p.healthy++
		if p.healthy < 2 {
			return false
		}
		p.paused = false
	}
	return true
}

type identityDeltaRun struct {
	ID int64
	IdentityScope
	ScopeKey, SnapshotID, State, Mode, Owner string
	ObservedAt, ReceivedAt                   time.Time
	Interval, Expected, Cursor, Batch        int
	DiffCursor, ExitCursor                   string
	ExitsComplete                            bool
}

func deltaBegin(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT set_config('lock_timeout','100ms',true),set_config('statement_timeout','10s',true),set_config('proxy_sentinel.identity_delta','on',true)`); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func deltaOwn(ctx context.Context, tx *sql.Tx, r identityDeltaRun) error {
	var valid bool
	err := tx.QueryRowContext(ctx, `SELECT lease_owner=$2 AND lease_until>clock_timestamp() FROM identity_delta_runs WHERE run_id=$1 FOR UPDATE`, r.ID, r.Owner).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrIdentityLeaseExpired
	}
	return nil
}

func (s *PostgresStore) claimIdentityDelta(ctx context.Context) (identityDeltaRun, error) {
	var r identityDeltaRun
	tx, err := deltaBegin(ctx, s.db)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('identity-delta-claim',7195))`).Scan(&locked); err != nil {
		return r, err
	}
	if !locked {
		return r, sql.ErrNoRows
	}
	// A lease is global across all materializer processes, not just a goroutine.
	var busy bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_delta_runs WHERE lease_owner<>'' AND lease_until>now())`).Scan(&busy); err != nil {
		return r, err
	}
	if busy {
		return r, sql.ErrNoRows
	}
	// Scope keys are canonical Go JSON, so join on their decoded fields instead
	// of JSONB's different whitespace/key order serialization.
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_delta_runs(scope_key,source,sensor_id,campus_id,access_domain,snapshot_id,observed_at,received_at,interval_seconds,expected_members)
 SELECT st.scope_key,j.source,j.sensor_id,j.campus_id,j.access_domain,j.snapshot_id,j.observed_at,f.received_at,f.interval_seconds,f.session_count
 FROM identity_snapshot_projection_jobs j JOIN identity_full_snapshots f USING(source,sensor_id,campus_id,access_domain,snapshot_id)
 JOIN identity_delta_settings st ON st.scope_key::jsonb->>'source'=j.source AND st.scope_key::jsonb->>'sensor_id'=j.sensor_id AND st.scope_key::jsonb->>'campus_id'=j.campus_id AND st.scope_key::jsonb->>'access_domain'=j.access_domain
 WHERE st.mode IN ('shadow','delta')
 AND NOT EXISTS(SELECT 1 FROM identity_delta_runs a WHERE a.scope_key=st.scope_key AND a.state<>'completed')
 ORDER BY j.observed_at,j.snapshot_id LIMIT 1 ON CONFLICT DO NOTHING`)
	if err != nil {
		return r, err
	}
	r.Owner = fmt.Sprintf("%d-%s", time.Now().UnixNano(), s.sensorID)
	err = tx.QueryRowContext(ctx, `UPDATE identity_delta_runs r SET lease_owner=$1,lease_until=now()+interval '30 seconds'
 WHERE r.run_id=(SELECT a.run_id FROM identity_delta_runs a JOIN identity_delta_settings st USING(scope_key)
 WHERE a.state NOT IN ('completed','failed') AND st.mode IN ('shadow','delta')
 AND NOT(a.state='ready' AND st.mode='shadow') ORDER BY a.run_id LIMIT 1 FOR UPDATE OF a SKIP LOCKED)
 RETURNING r.run_id,r.scope_key,r.source,r.sensor_id,r.campus_id,r.access_domain,r.snapshot_id,r.observed_at,r.received_at,r.interval_seconds,r.expected_members,r.state,r.member_cursor,r.diff_cursor,r.exit_cursor,r.exits_complete,r.batch_size,(SELECT mode FROM identity_delta_settings WHERE scope_key=r.scope_key)`, r.Owner).Scan(&r.ID, &r.ScopeKey, &r.Source, &r.SensorID, &r.CampusID, &r.AccessDomain, &r.SnapshotID, &r.ObservedAt, &r.ReceivedAt, &r.Interval, &r.Expected, &r.State, &r.Cursor, &r.DiffCursor, &r.ExitCursor, &r.ExitsComplete, &r.Batch, &r.Mode)
	if err != nil {
		return r, err
	}
	return r, tx.Commit()
}

func deltaMember(snapshot IdentitySnapshot, eventIndex int) (identityDeltaMember, error) {
	state := BuildIdentityState(snapshot.Events[eventIndex : eventIndex+1])
	if len(state.Sessions) != 1 {
		return identityDeltaMember{}, fmt.Errorf("snapshot member has no unique session")
	}
	session := state.Sessions[0]
	// Preserve the existing NCU login-generation handling.
	generation := stringFromMap(snapshot.Events[eventIndex].Payload, "source_login_generation")
	if seconds, e := strconv.ParseInt(generation, 10, 64); e == nil && seconds > 0 && strconv.FormatInt(seconds, 10) == generation && (strings.HasPrefix(snapshot.Source, "srun4k:") || snapshot.Source == "ncu-srun4k") && !time.Unix(seconds, 0).After(snapshot.ObservedAt) {
		session.StartedAt = time.Unix(seconds, 0).UTC().Format(time.RFC3339Nano)
	}
	raw, err := json.Marshal(session)
	return identityDeltaMember{Ordinal: eventIndex + 1, Key: session.SessionID + "\x1f" + session.IP, SessionID: session.SessionID, IP: session.IP, AccountID: session.AccountID, Fingerprint: identityMemberFingerprint(session), Document: raw}, err
}

// Decode once per process/run, retaining the bounded current inventory across
// pressure pauses. Durable ordinals resume after restart; that restart may
// re-read the retained source but cannot skip members or request a resend.
func (s *PostgresStore) stageIdentityDelta(ctx context.Context, r identityDeltaRun) error {
	if s.identityDeltaSnapshot == nil || s.identityDeltaSnapshotRun != r.ID {
		var raw []byte
		if err := s.db.QueryRowContext(ctx, `SELECT document FROM identity_full_snapshots WHERE source=$1 AND sensor_id=$2 AND campus_id=$3 AND access_domain=$4 AND snapshot_id=$5`, r.Source, r.SensorID, r.CampusID, r.AccessDomain, r.SnapshotID).Scan(&raw); err != nil {
			return err
		}
		var snapshot IdentitySnapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			return err
		}
		s.identityDeltaSnapshot = &snapshot
		s.identityDeltaSnapshotRun = r.ID
	}
	snapshot := s.identityDeltaSnapshot
	captureOrigin := "source_timestamp"
	captureStarted := snapshot.CaptureStartedAt
	if captureStarted == nil && r.Source == "ncu-srun4k" {
		// The deployed stabilized NCU reader has a 45 s total context budget.
		// Retain a wider 60 s uncertainty interval for pre-upgrade documents; do
		// not claim that this was a measured start or discard the pending input.
		bound := r.ObservedAt.Add(-time.Minute)
		captureStarted = &bound
		captureOrigin = "bounded_legacy_reader"
	}
	if captureStarted == nil {
		captureOrigin = "missing"
	}
	if len(snapshot.Events) != r.Expected {
		return fmt.Errorf("snapshot membership count differs from manifest")
	}
	for offset := r.Cursor; offset < len(snapshot.Events); {
		age, blocked, loadErr := s.identityDeltaLoad(ctx)
		if loadErr != nil {
			return loadErr
		}
		if age > 5*time.Second || blocked {
			return errIdentityDeltaPressure
		}
		batch := make([]identityDeltaMember, 0, max(1, min(r.Batch, identityDeltaMaxMembers)))
		size := 0
		for offset+len(batch) < len(snapshot.Events) && len(batch) < max(1, min(r.Batch, identityDeltaMaxMembers)) {
			member, err := deltaMember(*snapshot, offset+len(batch))
			if err != nil {
				return err
			}
			n := len(member.Document) + len(member.Key) + 128
			if n > identityDeltaMaxBytes {
				return errIdentityDeltaOversize
			}
			if size+n > identityDeltaMaxBytes {
				break
			}
			batch = append(batch, member)
			size += n
		}
		data, _ := json.Marshal(batch)
		if err := s.stageIdentityDeltaChunk(ctx, r, data, offset+len(batch)); err != nil {
			return err
		}
		offset += len(batch)
	}
	tx, err := deltaBegin(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = deltaOwn(ctx, tx, r); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_delta_members WHERE run_id=$1`, r.ID).Scan(&count); err != nil {
		return err
	}
	if count != r.Expected {
		return fmt.Errorf("snapshot has duplicate member keys")
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_delta_runs SET state='validated',capture_started_at=$2,capture_origin=$3 WHERE run_id=$1`, r.ID, captureStarted, captureOrigin)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.identityDeltaSnapshot = nil
	return nil
}

// Recover the bounded batch after a transient stall instead of permanently
// multiplying claim/apply/release commits. Pressure pauses never change its size.
func nextIdentityDeltaBatch(size int, elapsed time.Duration, err error) int {
	if errors.Is(err, errIdentityDeltaPressure) {
		return size
	}
	if err != nil || elapsed > 5*time.Second {
		return max(1, size/2)
	}
	if elapsed < time.Second && size < identityDeltaMaxMembers {
		return min(identityDeltaMaxMembers, size*2)
	}
	return size
}

func (s *PostgresStore) processIdentityDelta(ctx context.Context) (bool, error) {
	r, err := s.claimIdentityDelta(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	start := time.Now()
	switch r.State {
	case "receiving":
		err = s.stageIdentityDelta(ctx, r)
	case "validated", "diffing":
		step, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		err = s.diffIdentityDelta(step, r)
	case "ready", "applying":
		step, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		err = s.applyIdentityDelta(step, r)
	default:
		err = fmt.Errorf("unsupported calibration state %s", r.State)
	}
	report, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errorText := ""
	if err != nil {
		errorText = err.Error()
	}
	nextBatch := r.Batch
	if r.State != "receiving" {
		nextBatch = nextIdentityDeltaBatch(r.Batch, time.Since(start), err)
	}
	_, releaseErr := s.db.ExecContext(report, `UPDATE identity_delta_runs SET lease_owner='',lease_until=NULL,last_error=$3,state=CASE WHEN $5 THEN 'failed' ELSE state END,batch_size=$4 WHERE run_id=$1 AND lease_owner=$2`, r.ID, r.Owner, errorText, nextBatch, errors.Is(err, errIdentityDeltaOversize) || errors.Is(err, errIdentityDeltaStaleSnapshot))
	log.Printf("identity_delta_step run_id=%d state=%s mode=%s elapsed_ms=%d failed=%t batch_size=%d next_batch_size=%d", r.ID, r.State, r.Mode, time.Since(start).Milliseconds(), err != nil, r.Batch, nextBatch)
	if err != nil {
		return true, err
	}
	return true, releaseErr
}

func (s *PostgresStore) stageIdentityDeltaChunk(ctx context.Context, r identityDeltaRun, data []byte, next int) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := deltaBegin(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = deltaOwn(ctx, tx, r); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_delta_members(run_id,ordinal,member_key,session_id,ip,account_id,fingerprint,document)
 SELECT $1,m.ordinal,m.member_key,m.session_id,m.ip,m.account_id,m.fingerprint,m.document FROM jsonb_to_recordset($2::jsonb) m(ordinal integer,member_key text,session_id text,ip text,account_id text,fingerprint text,document jsonb)
 ON CONFLICT(run_id,member_key) DO NOTHING`, r.ID, data)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_delta_runs SET member_cursor=$3,lease_until=now()+interval '30 seconds' WHERE run_id=$1 AND lease_owner=$2`, r.ID, r.Owner, next)
	if err != nil {
		return err
	}
	return tx.Commit()
}
