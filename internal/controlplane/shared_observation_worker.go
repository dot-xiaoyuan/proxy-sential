package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
	"sync/atomic"
	"time"
)

type sharedObservationDocument struct {
	Window     sharedaccess.Window             `json:"window"`
	Assessment sharedaccess.BehaviorAssessment `json:"assessment"`
	Result     sharedaccess.Result             `json:"result"`
}

var newSharedObservationLeaseToken = func() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var sharedObservationEmptyClaims atomic.Int64
var sharedObservationClaimAttempts atomic.Int64

func (s *Server) startSharedObservationWorker() error {
	if s.operations.db == nil {
		return fmt.Errorf("shared observation requires PostgreSQL")
	}
	if _, ok := s.reader.(store.SharedObservationReader); !ok {
		return fmt.Errorf("shared observation requires ClickHouse reader")
	}
	if len(s.sharedConfig.Sources) == 0 || len(s.sharedConfig.IdentityMappings) == 0 {
		return fmt.Errorf("shared observation requires capture sources and identity mappings")
	}
	if err := s.persistSharedObservationMappings(context.Background()); err != nil {
		return err
	}
	if resolver, ok := s.reader.(interface {
		ResolveSharedGateway(context.Context, sharedaccess.Config, time.Time) (bool, error)
	}); ok {
		go func() {
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				did, err := resolver.ResolveSharedGateway(ctx, s.sharedConfig, time.Now().UTC())
				cancel()
				if err != nil {
					log.Printf("shared gateway resolution failed: %v", err)
				}
				if !did || err != nil {
					time.Sleep(time.Second)
				}
			}
		}()
	}
	raw, _ := json.Marshal(sharedaccess.ObservationPolicy())
	if _, err := s.operations.db.ExecContext(context.Background(), `INSERT INTO account_policy_definitions(id,document) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET document=EXCLUDED.document`, sharedaccess.ObservationPolicyID, raw); err != nil {
		return err
	}
	if archive, ok := s.reader.(interface {
		ArchiveSharedObservation(context.Context) (bool, error)
	}); ok {
		go func() {
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				did, err := archive.ArchiveSharedObservation(ctx)
				cancel()
				if err != nil {
					log.Printf("shared observation archive failed: %v", err)
				}
				if !did || err != nil {
					time.Sleep(time.Minute)
				} else {
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()
	}
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			did, err := s.processSharedObservationWake(ctx)
			cancel()
			if err != nil {
				log.Printf("shared observation wake failed: %v", err)
			}
			if !did || err != nil {
				time.Sleep(200 * time.Millisecond)
			}
		}
	}()
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.maintainSharedObservationWakes(ctx); err != nil {
				log.Printf("shared wake retention failed: %v", err)
			}
			if err := s.reconcileSharedObservationGaps(ctx); err != nil {
				log.Printf("shared observation reconciliation failed: %v", err)
			}
			if err := s.logSharedObservationMetrics(ctx); err != nil {
				log.Printf("shared observation metrics failed: %v", err)
			}
			cancel()
			time.Sleep(time.Minute)
		}
	}()
	// No action worker, notification queue or controller is reachable from here.
	var asyncMode atomic.Bool
	var initialMode string
	if err := s.operations.db.QueryRowContext(context.Background(), `SELECT mode FROM shared_observation_wake_mode WHERE singleton`).Scan(&initialMode); err != nil {
		return err
	}
	asyncMode.Store(initialMode == "async")
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			var mode string
			err := s.operations.db.QueryRowContext(ctx, `SELECT mode FROM shared_observation_wake_mode WHERE singleton`).Scan(&mode)
			cancel()
			if err == nil {
				asyncMode.Store(mode == "async")
			} else {
				log.Printf("shared wake mode refresh failed: %v", err)
			}
			time.Sleep(5 * time.Second)
		}
	}()
	chSlots := make(chan struct{}, 4)
	// Keep one expiry worker reserved and allow up to two realtime workers to
	// borrow expiry work only after their realtime claim finds no ready job.
	expiryBorrowSlots := make(chan struct{}, 2)
	for i := 0; i < 8; i++ {
		workerIndex := i
		lane := sharedObservationWorkerLane(i)
		go func() {
			for {
				if workerIndex >= 2 && !asyncMode.Load() {
					time.Sleep(time.Second)
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				did, err := s.processSharedObservationWithLimit(ctx, time.Now().UTC(), chSlots, lane)
				cancel()
				if shouldBorrowSharedObservationExpiry(lane, asyncMode.Load(), did, err) {
					select {
					case expiryBorrowSlots <- struct{}{}:
						expiryCtx, expiryCancel := context.WithTimeout(context.Background(), 30*time.Second)
						did, err = s.processSharedObservationWithLimit(expiryCtx, time.Now().UTC(), chSlots, "expiry_borrowed")
						expiryCancel()
						<-expiryBorrowSlots
					default:
					}
				}
				if err != nil {
					log.Printf("shared observation task failed: %v", err)
				}
				if !did || err != nil {
					time.Sleep(time.Second)
				}
			}
		}()
	}
	return nil
}

func sharedObservationWorkerLane(index int) string {
	if index == 1 {
		return "expiry"
	}
	return "realtime_new"
}

func shouldBorrowSharedObservationExpiry(lane string, asyncMode, did bool, err error) bool {
	return lane == "realtime_new" && asyncMode && !did && err == nil
}

func sharedObservationExpiryLane(lane string) bool {
	return lane == "expiry" || lane == "expiry_borrowed"
}

func (s *Server) processSharedObservation(ctx context.Context, now time.Time) (bool, error) {
	return s.processSharedObservationWithLimit(ctx, now, nil, "realtime_new")
}

func (s *Server) processSharedObservationWithLimit(ctx context.Context, now time.Time, chSlots chan struct{}, lane string) (bool, error) {
	started := time.Now()
	var id string
	var scope store.SharedObservationScope
	var revision int64
	var previous []byte
	var dependencyAt time.Time
	var newDependency bool
	token, err := newSharedObservationLeaseToken()
	if err != nil {
		return false, err
	}
	claimStarted := time.Now()
	var readDuration, identityDuration time.Duration
	scopeJSON, _ := json.Marshal(s.sharedConfig.Sources)
	group, order := sharedObservationClaimOrder(lane)
	claimSQL := fmt.Sprintf(`WITH candidate AS (
 SELECT j.job_id FROM shared_observation_jobs j CROSS JOIN shared_observation_wake_mode m WHERE m.singleton
 AND NOT j.expired AND j.next_attempt_at<=now()
 AND (j.lease_token='' OR j.lease_until<now())
 AND (($4='realtime' AND (j.revision>j.completed_revision OR (m.mode<>'async' AND j.last_event_at+($2::integer*interval '1 second')>now())))
   OR ($4='expiry' AND j.revision=j.completed_revision AND (m.mode='async' OR j.last_event_at+($2::integer*interval '1 second')<=now())))
 AND (j.sensor_id,j.campus_id,j.access_domain) IN (SELECT sensor_id,campus_id,access_domain FROM jsonb_to_recordset($1::jsonb) r(sensor_id text,campus_id text,access_domain text))
 -- The mode row is shared by all claimers. Locking it here makes the other
 -- seven workers skip the entire candidate even while jobs are pending.
 ORDER BY %s LIMIT 1 FOR UPDATE OF j SKIP LOCKED)
 UPDATE shared_observation_jobs j SET lease_token=$3,lease_until=now()+interval '45 seconds'
 FROM candidate WHERE j.job_id=candidate.job_id
 RETURNING j.job_id,j.sensor_id,j.campus_id,j.access_domain,host(j.ip),j.revision,j.last_document,j.last_dependency_at,j.dirty_since<=j.last_dependency_at`, order)
	// Only a transient, random-token lease is changed here. Losing an unflushed
	// claim on a database crash leaves the durable job pending; a replacement
	// claim has a different token, so the old worker cannot publish or ACK it.
	// No external actions occur between claim and the durable result transaction.
	claimTx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	if _, err = claimTx.ExecContext(ctx, `SET LOCAL synchronous_commit = off`); err == nil {
		err = claimTx.QueryRowContext(ctx, claimSQL, scopeJSON, s.sharedConfig.FreshnessSeconds, token, group).Scan(&id, &scope.SensorID, &scope.CampusID, &scope.AccessDomain, &scope.IP, &revision, &previous, &dependencyAt, &newDependency)
	}
	if err == nil {
		err = claimTx.Commit()
	} else {
		_ = claimTx.Rollback()
	}
	claimDuration := time.Since(claimStarted)
	sharedObservationClaimAttempts.Add(1)
	if errors.Is(err, sql.ErrNoRows) {
		sharedObservationEmptyClaims.Add(1)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// A new event increments the revision while the worker reads external evidence.
	failure := func(cause error) (bool, error) {
		sharedObservationFailures.Add(1)
		report, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, e := s.operations.db.ExecContext(report, `UPDATE shared_observation_jobs SET attempts=attempts+1,last_error='processing_failed',next_attempt_at=now()+interval '5 seconds',lease_token='',lease_until=NULL WHERE job_id=$1 AND lease_token=$2 AND revision=$3`, id, token, revision)
		if e != nil {
			return true, fmt.Errorf("%w; report: %v", cause, e)
		}
		return true, cause
	}
	reader := s.reader.(store.SharedObservationReader)
	var doc sharedObservationDocument
	var w sharedaccess.Window
	var item sharedaccess.BehaviorAssessment
	if sharedObservationExpiryLane(lane) && len(previous) > 0 {
		if err = json.Unmarshal(previous, &doc); err != nil {
			return failure(err)
		}
		w, item = doc.Window, doc.Assessment
		item.Current = false
	} else {
		readStarted := time.Now()
		if chSlots != nil {
			select {
			case chSlots <- struct{}{}:
			case <-ctx.Done():
				return failure(ctx.Err())
			}
		}
		w, item, err = reader.ReadSharedObservation(ctx, scope, s.sharedConfig, now)
		readDuration = time.Since(readStarted)
		if chSlots != nil {
			<-chSlots
		}
		if err != nil {
			return failure(err)
		}
	}
	if !item.Current && len(previous) > 0 {
		if err = json.Unmarshal(previous, &doc); err != nil {
			return failure(err)
		}
		w, item = doc.Window, doc.Assessment
		item.Current = false
	}
	if item.Current && len(previous) > 0 && w.StrongAnchor == "" {
		var prev sharedObservationDocument
		if json.Unmarshal(previous, &prev) == nil && prev.Window.StrongAnchor != "" {
			w.StrongAnchor = prev.Window.StrongAnchor
			w.AssociatedClients = prev.Window.AssociatedClients
			if prev.Window.DeviceLowerBound > w.DeviceLowerBound {
				w.DeviceLowerBound = prev.Window.DeviceLowerBound
			}
		}
	}
	if s.sharedConfig.SkipCaptureVerification && item.Current {
		w.CoverageVerified = true
		w.Complete = true
	}
	var identityEvidence []policy.Session
	result := sharedaccess.EvaluateObservation(w, s.sharedConfig, nil, now)
	if !item.Current && len(previous) > 0 {
		result = doc.Result
		result.State = "insufficient"
		result.Reasons = []string{"shared_evidence_expired"}
	}
	anchorSatisfied := w.StrongAnchor != "" && w.DeviceLowerBound >= s.sharedConfig.DeviceBound()
	diversitySatisfied := s.sharedConfig.SkipCaptureVerification && len(item.SignalGroups) >= 2
	captureBypass := s.sharedConfig.SkipCaptureVerification
	if item.Current && (anchorSatisfied || diversitySatisfied || captureBypass) && w.Complete && w.CoverageVerified {
		identityStarted := time.Now()
		mapping, mapErr := s.sharedConfig.Mapping(w)
		if mapErr == nil {
			authority, e := newIdentityAuthorityResolver(s).resolve(ctx, store.IdentityScope{Source: mapping.Source, SensorID: mapping.IdentitySensorID, CampusID: mapping.IdentityCampusID, AccessDomain: mapping.IdentityAccessDomain})
			if e != nil {
				return failure(e)
			}
			if authority.registered {
				sessions, e := reader.SharedIdentitySessions(ctx, mapping, w.IP, w.From, now, authority.interval)
				if e != nil {
					return failure(e)
				}
				if s.sharedConfig.SkipCaptureVerification {
					for i := range sessions {
						sessions[i].IdentityIssue = ""
					}
				}
				identityEvidence = sessions
				result = sharedaccess.EvaluateObservation(w, s.sharedConfig, sessions, now)
				if !s.sharedConfig.SkipCaptureVerification {
					for _, session := range sessions {
						if session.IdentityIssue != "" {
							result.Reasons = append(result.Reasons, session.IdentityIssue)
							break
						}
					}
				}
			} else {
				result.Reasons = []string{"identity_source_unregistered"}
			}
		}
		identityDuration = time.Since(identityStarted)
	}
	evaluatedAt := now.Add(time.Since(started))
	if item.Current && identityEvidence != nil {
		result = sharedaccess.EvaluateObservation(w, s.sharedConfig, identityEvidence, evaluatedAt)
		if !s.sharedConfig.SkipCaptureVerification {
			for _, session := range identityEvidence {
				if session.IdentityIssue != "" {
					result.Reasons = append(result.Reasons, session.IdentityIssue)
					break
				}
			}
		}
	}
	decision := sharedaccess.NewObservationDecision(w, result, s.sharedConfig, evaluatedAt)
	if decision.Result == "expired" {
		item.Current = false
	}
	decision.IdentityEvidence = identityEvidence
	doc = sharedObservationDocument{Window: w, Assessment: item, Result: result}
	raw, err := json.Marshal(doc)
	if err != nil {
		return failure(err)
	}
	persistStarted := time.Now()
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	// Result, evidence, audit and ACK remain one synchronously durable commit.
	if _, err = tx.ExecContext(ctx, `SET LOCAL synchronous_commit = on`); err != nil {
		_ = tx.Rollback()
		return failure(err)
	}
	if err = store.PersistSharedObservationTx(ctx, tx, item); err != nil {
		_ = tx.Rollback()
		return failure(err)
	}
	if err = store.EnqueueSharedDeviceProfileJobsForObservations(ctx, tx, []store.SharedObservationProfileKey{
		{SensorID: item.SensorID, CampusID: item.CampusID, EndpointID: item.EndpointID, IP: item.IP, ObservedAt: item.LastSeen},
	}); err != nil {
		_ = tx.Rollback()
		return failure(err)
	}
	if err = persistSharedObservationDecision(ctx, tx, decision); err != nil {
		_ = tx.Rollback()
		return failure(err)
	}
	next := decision.EvidenceExpiresAt
	var wakeMode string
	if err = tx.QueryRowContext(ctx, `SELECT mode FROM shared_observation_wake_mode WHERE singleton`).Scan(&wakeMode); err != nil {
		_ = tx.Rollback()
		return failure(err)
	}
	// Take the job lock only after the potentially slow evidence and audit writes.
	// A concurrent enqueue may advance the revision meanwhile; rolling this
	// transaction back then removes every stale observation and decision write.
	var currentRevision int64
	var currentToken string
	if err = tx.QueryRowContext(ctx, `SELECT revision,lease_token FROM shared_observation_jobs WHERE job_id=$1 FOR UPDATE`, id).Scan(&currentRevision, &currentToken); err != nil {
		_ = tx.Rollback()
		return failure(err)
	}
	if currentRevision != revision || currentToken != token {
		sharedObservationVersionConflicts.Add(1)
		_ = tx.Rollback()
		if currentToken == token {
			report, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err = s.operations.db.ExecContext(report, `UPDATE shared_observation_jobs SET lease_token='',lease_until=NULL,next_attempt_at=now() WHERE job_id=$1 AND lease_token=$2`, id, token); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	if wakeMode != "async" && decision.Result != "matched" {
		next = evaluatedAt.Add(5 * time.Second)
	}
	if !next.After(evaluatedAt) {
		next = evaluatedAt.Add(time.Minute)
	}
	attributionState := "insufficient"
	if result.AccountID != "" {
		attributionState = "resolved"
	}
	newTask := sharedObservationNewDependency(lane, newDependency)
	_, err = tx.ExecContext(ctx, `UPDATE shared_observation_jobs SET completed_revision=$2,completed_at=clock_timestamp(),next_attempt_at=$3,last_error='',attempts=0,expired=$4,last_document=$5,last_result=$6,coverage_state=$7,attribution_state=$8,lease_token='',lease_until=NULL,last_decision_latency_ms=CASE WHEN $10 THEN GREATEST(0,round(extract(epoch FROM clock_timestamp()-$9::timestamptz)*1000)) ELSE last_decision_latency_ms END WHERE job_id=$1`, id, revision, next, decision.Result == "expired", raw, decision.Result, item.CoverageState, attributionState, dependencyAt, newTask)
	if err != nil {
		_ = tx.Rollback()
		return failure(err)
	}
	if err = tx.Commit(); err != nil {
		sharedObservationFailures.Add(1)
		return true, err
	}
	if wakeMode == "async" {
		latency := time.Since(dependencyAt)
		if latency < 0 {
			latency = 0
		}
		if newTask {
			sharedDecisionLatencies.record(time.Now(), latency)
		}
		log.Printf("shared_observation_decision job_id=%s revision=%d lane=%s result=%s new_dependency=%t dependency_at=%s latency_ms=%d claim_ms=%d read_ms=%d identity_ms=%d persist_ms=%d", id, revision, lane, decision.Result, newTask, dependencyAt.UTC().Format(time.RFC3339Nano), latency.Milliseconds(), claimDuration.Milliseconds(), readDuration.Milliseconds(), identityDuration.Milliseconds(), time.Since(persistStarted).Milliseconds())
	}
	return true, nil
}

func sharedObservationClaimOrder(lane string) (string, string) {
	switch lane {
	case "realtime_old":
		return "realtime", "next_attempt_at,dirty_since,job_id"
	case "expiry", "expiry_borrowed":
		return "expiry", "next_attempt_at,dirty_since,job_id"
	default:
		// Serve the oldest fresh dependency first. Newer handshake batches must
		// not repeatedly overtake work that is approaching the 30-second target.
		// Older work is selected when the recent queue empties, while the
		// dedicated expiry lane makes progress even under sustained arrivals.
		return "realtime", "CASE WHEN last_dependency_at>=now()-interval '5 minutes' THEN 0 ELSE 1 END,last_dependency_at,job_id"
	}
}

func sharedObservationNewDependency(lane string, marked bool) bool {
	return !sharedObservationExpiryLane(lane) && marked
}

func persistSharedObservationDecision(ctx context.Context, tx *sql.Tx, d sharedaccess.ObservationDecision) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if d.Result == "matched" {
		actionIDs := []string{}
		if violationObservationOnly() {
			actionIDs = append(actionIDs, "shared-record:"+d.DecisionID)
		}
		execution := policy.Execution{ID: d.ExecutionID, PolicyID: d.PolicyID, AccountID: d.AccountID, State: "recorded", LastEvaluated: d.EvaluatedAt, EvidenceIDs: []string{d.ObservationID}, Definition: sharedaccess.ObservationPolicy(), Stages: []policy.StageState{{Status: "recorded", ActionIDs: actionIDs, ExecuteCount: 0}}}
		data, e := json.Marshal(execution)
		if e != nil {
			return e
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO shared_observation_executions(execution_id,account_id,evidence_version,state,document,expires_at) VALUES($1,$2,$3,'recorded',$4,$5) ON CONFLICT DO NOTHING`, d.ExecutionID, d.AccountID, d.EvidenceVersion, data, d.EvidenceExpiresAt)
		if err != nil {
			return err
		}
	}
	if d.Result == "expired" {
		_, err = tx.ExecContext(ctx, `UPDATE shared_observation_executions SET state='expired',document=jsonb_set(document,'{state}','"expired"') WHERE evidence_version=$1 AND state<>'expired'`, d.EvidenceVersion)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO policy_decision_records(decision_id,execution_id,policy_id,policy_revision,account_id,known,violated,evaluated_at,document,trigger_type,subject_ip,result,observation_id,evidence_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'shared_access',$10::inet,$11,$12,$13) ON CONFLICT(decision_id) DO NOTHING`, d.DecisionID, d.ExecutionID, d.PolicyID, d.PolicyRevision, d.AccountID, d.Known, d.Violated, d.EvaluatedAt, raw, d.IP, d.Result, d.ObservationID, d.EvidenceVersion)
	if err != nil || d.Result != "matched" || !violationObservationOnly() {
		return err
	}
	// A terminal record-only action is visible in the ordinary action ledger.
	// Workers claim only pending actions; this row can never be delivered.
	_, err = tx.ExecContext(ctx, `INSERT INTO enforcement_actions(action_id,idempotency_key,action_type,subject_type,subject_id,account_id,ip,campus_id,status,mode,evidence_ids,ruleset_version,policy_parameters,created_by,created_at)
		VALUES($1,$1,'disconnect','account',$2,$2,$3::inet,NULLIF($4,''),'recorded','record_only',jsonb_build_array($5::text),$6,
		jsonb_build_object('execution_id',$7::text,'policy_id',$8::text,'decision_id',$9::text,'policy_revision',$10::bigint,'evidence_version',$11::text,'observation_id',$5::text),
		'shared_observation', $12) ON CONFLICT(idempotency_key) DO NOTHING`, "shared-record:"+d.DecisionID, d.AccountID, d.IP, d.CampusID, d.ObservationID, d.EvidenceVersion, d.ExecutionID, d.PolicyID, d.DecisionID, d.PolicyRevision, d.EvidenceVersion, d.EvaluatedAt)
	if err != nil {
		return err
	}
	// Enabled reporting channels receive a terminal record in the normal report
	// ledger. The delivery worker claims queued/sending rows only.
	_, err = tx.ExecContext(ctx, `INSERT INTO behavior_report_outbox(report_id,idempotency_key,channel_id,event_type,subject_type,subject_id,account_id,ip,occurred_at,payload,status)
		SELECT 'shared-record:'||$1||':'||channel_id,'shared-record:'||$1||':'||channel_id,channel_id,'proxy_behavior','account',$2,$2,$3,$4,
		jsonb_build_object('policy_decision_id',$1::text,'policy_id',$5::text,'policy_revision',$6::bigint,'observation_id',$7::text,
		'evidence_version',$8::text,'campus_id',$9::text,'access_domain',$10::text,'execution_mode','record_only','external_request_sent',false),
		'recorded' FROM behavior_report_channels WHERE enabled=true
		ON CONFLICT(idempotency_key) DO NOTHING`, d.DecisionID, d.AccountID, d.IP, d.EvaluatedAt, d.PolicyID, d.PolicyRevision, d.ObservationID, d.EvidenceVersion, d.CampusID, d.AccessDomain)
	return err
}
