package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
	"time"
)

type sharedObservationDocument struct {
	Window     sharedaccess.Window             `json:"window"`
	Assessment sharedaccess.BehaviorAssessment `json:"assessment"`
	Result     sharedaccess.Result             `json:"result"`
}

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
	// No action worker, notification queue or controller is reachable from here.
	for i := 0; i < 2; i++ {
		go func() {
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				did, err := s.processSharedObservation(ctx, time.Now().UTC())
				cancel()
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

func (s *Server) processSharedObservation(ctx context.Context, now time.Time) (bool, error) {
	started := time.Now()
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var id string
	var scope store.SharedObservationScope
	var revision int64
	var previous []byte
	scopeJSON, _ := json.Marshal(s.sharedConfig.Sources)
	err = tx.QueryRowContext(ctx, `SELECT job_id,sensor_id,campus_id,access_domain,host(ip),revision,last_document FROM shared_observation_jobs WHERE NOT expired AND next_attempt_at<=now() AND (sensor_id,campus_id,access_domain) IN (SELECT sensor_id,campus_id,access_domain FROM jsonb_to_recordset($1::jsonb) r(sensor_id text,campus_id text,access_domain text)) ORDER BY next_attempt_at,dirty_since,job_id FOR UPDATE SKIP LOCKED LIMIT 1`, scopeJSON).Scan(&id, &scope.SensorID, &scope.CampusID, &scope.AccessDomain, &scope.IP, &revision, &previous)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Keep the row lock through commit. Failed/terminated workers leave no ACK.
	failure := func(cause error) (bool, error) {
		_ = tx.Rollback()
		report, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, e := s.operations.db.ExecContext(report, `UPDATE shared_observation_jobs SET attempts=attempts+1,last_error='processing_failed',next_attempt_at=now()+interval '5 seconds' WHERE job_id=$1`, id)
		if e != nil {
			return true, fmt.Errorf("%w; report: %v", cause, e)
		}
		return true, cause
	}
	reader := s.reader.(store.SharedObservationReader)
	var doc sharedObservationDocument
	w, item, err := reader.ReadSharedObservation(ctx, scope, s.sharedConfig, now)
	if err != nil {
		return failure(err)
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
	if err = store.PersistSharedObservationTx(ctx, tx, item); err != nil {
		return failure(err)
	}
	if err = store.EnqueueSharedDeviceProfileJobsForObservations(ctx, tx, []store.SharedObservationProfileKey{
		{SensorID: item.SensorID, CampusID: item.CampusID, EndpointID: item.EndpointID, IP: item.IP, ObservedAt: item.LastSeen},
	}); err != nil {
		return failure(err)
	}
	if err = persistSharedObservationDecision(ctx, tx, decision); err != nil {
		return failure(err)
	}
	next := decision.EvidenceExpiresAt
	if decision.Result != "matched" {
		next = now.Add(5 * time.Second)
	}
	attributionState := "insufficient"
	if result.AccountID != "" {
		attributionState = "resolved"
	}
	_, err = tx.ExecContext(ctx, `UPDATE shared_observation_jobs SET completed_revision=$2,completed_at=clock_timestamp(),next_attempt_at=$3,last_error='',attempts=0,expired=$4,last_document=$5,last_result=$6,coverage_state=$7,attribution_state=$8 WHERE job_id=$1`, id, revision, next, decision.Result == "expired", raw, decision.Result, item.CoverageState, attributionState)
	if err != nil {
		return failure(err)
	}
	return true, tx.Commit()
}

func persistSharedObservationDecision(ctx context.Context, tx *sql.Tx, d sharedaccess.ObservationDecision) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if d.Result == "matched" {
		execution := policy.Execution{ID: d.ExecutionID, PolicyID: d.PolicyID, AccountID: d.AccountID, State: "recorded", LastEvaluated: d.EvaluatedAt, EvidenceIDs: []string{d.ObservationID}, Definition: sharedaccess.ObservationPolicy(), Stages: []policy.StageState{{Status: "recorded", ActionIDs: []string{}, ExecuteCount: 0}}}
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
	return err
}
