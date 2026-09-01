package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type operationsQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *operationsState) beginLocked() {
	s.lockErr = nil
	if s.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err == nil {
		_, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations'))`)
	}
	if err == nil {
		err = s.reloadPostgres(ctx, tx)
	}
	if err != nil {
		if tx != nil {
			_ = tx.Rollback()
		}
		cancel()
		s.lockErr = fmt.Errorf("begin PostgreSQL operations transaction: %w", err)
		s.setHealthError(s.lockErr)
		return
	}
	s.tx = tx
	s.txCancel = cancel
}

func (s *operationsState) endLocked() {
	if s.tx == nil {
		return
	}
	var err error
	if s.lockErr != nil {
		err = s.tx.Rollback()
	} else {
		err = s.tx.Commit()
	}
	if err != nil && err != sql.ErrTxDone {
		s.setHealthError(fmt.Errorf("finish PostgreSQL operations transaction: %w", err))
	} else if s.lockErr == nil {
		s.setHealthError(nil)
	}
	s.tx = nil
	if s.txCancel != nil {
		s.txCancel()
		s.txCancel = nil
	}
}

func (s *operationsState) setHealthError(err error) {
	s.healthMu.Lock()
	s.healthErr = err
	s.healthMu.Unlock()
}

func (s *operationsState) health(ctx context.Context) error {
	s.healthMu.RLock()
	err := s.healthErr
	s.healthMu.RUnlock()
	if err != nil {
		return err
	}
	if s.db != nil {
		return s.db.PingContext(ctx)
	}
	return nil
}

func (s *operationsState) reloadPostgres(ctx context.Context, q operationsQuerier) error {
	doc := emptyOperationsDocument()
	if err := loadOrganization(ctx, q, &doc); err != nil {
		return err
	}
	if err := loadSLAPolicies(ctx, q, &doc); err != nil {
		return err
	}
	if err := loadCases(ctx, q, &doc); err != nil {
		return err
	}
	if err := loadConnectors(ctx, q, &doc); err != nil {
		return err
	}
	if err := loadActions(ctx, q, &doc); err != nil {
		return err
	}
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT setting_value FROM control_plane_settings WHERE setting_key='global_emergency_stop'`).Scan(&raw)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("load global emergency stop: %w", err)
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &doc.GlobalStop)
	}
	s.doc = doc
	return nil
}

func loadSLAPolicies(ctx context.Context, q operationsQuerier, doc *operationsDocument) error {
	rows, err := q.QueryContext(ctx, `SELECT policy_id,assessment_level,response_minutes,resolution_minutes,enabled FROM sla_policies`)
	if err != nil {
		return fmt.Errorf("load SLA policies: %w", err)
	}
	defer rows.Close()
	doc.SLAPolicies = map[string]SLAPolicy{}
	for rows.Next() {
		var item SLAPolicy
		if err := rows.Scan(&item.PolicyID, &item.AssessmentLevel, &item.ResponseMinutes, &item.ResolutionMinutes, &item.Enabled); err != nil {
			return err
		}
		doc.SLAPolicies[item.AssessmentLevel] = item
	}
	return rows.Err()
}

func loadOrganization(ctx context.Context, q operationsQuerier, doc *operationsDocument) error {
	rows, err := q.QueryContext(ctx, `SELECT campus_id, code, name, enabled FROM campuses`)
	if err != nil {
		return fmt.Errorf("load campuses: %w", err)
	}
	for rows.Next() {
		var item Campus
		if err := rows.Scan(&item.CampusID, &item.Code, &item.Name, &item.Enabled); err != nil {
			rows.Close()
			return err
		}
		doc.Campuses[item.CampusID] = item
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT building_id, campus_id, code, name, enabled FROM buildings`)
	if err != nil {
		return fmt.Errorf("load buildings: %w", err)
	}
	for rows.Next() {
		var item Building
		if err := rows.Scan(&item.BuildingID, &item.CampusID, &item.Code, &item.Name, &item.Enabled); err != nil {
			rows.Close()
			return err
		}
		doc.Buildings[item.BuildingID] = item
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT network_zone_id, campus_id, COALESCE(building_id,''), name, cidrs, ssids, vlans, enabled FROM network_zones`)
	if err != nil {
		return fmt.Errorf("load network zones: %w", err)
	}
	for rows.Next() {
		var item NetworkZone
		var cidrs, ssids, vlans []byte
		if err := rows.Scan(&item.NetworkZoneID, &item.CampusID, &item.BuildingID, &item.Name, &cidrs, &ssids, &vlans, &item.Enabled); err != nil {
			rows.Close()
			return err
		}
		_ = json.Unmarshal(cidrs, &item.CIDRs)
		_ = json.Unmarshal(ssids, &item.SSIDs)
		_ = json.Unmarshal(vlans, &item.VLANs)
		doc.NetworkZones[item.NetworkZoneID] = item
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT access_point_id, campus_id, COALESCE(building_id,''), COALESCE(network_zone_id,''), kind, name, COALESCE(host(management_ip),''), enabled FROM access_points`)
	if err != nil {
		return fmt.Errorf("load access points: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item AccessPoint
		if err := rows.Scan(&item.AccessPointID, &item.CampusID, &item.BuildingID, &item.NetworkZoneID, &item.Kind, &item.Name, &item.ManagementIP, &item.Enabled); err != nil {
			return err
		}
		doc.AccessPoints[item.AccessPointID] = item
	}
	return rows.Err()
}

func loadCases(ctx context.Context, q operationsQuerier, doc *operationsDocument) error {
	rows, err := q.QueryContext(ctx, `SELECT case_id, subject_type, subject_id, COALESCE(host(ip),''), COALESCE(account_id,''), COALESCE(endpoint_id,''), COALESCE(campus_id,''), COALESCE(department,''), COALESCE(person_type,''), COALESCE(building_id,''), COALESCE(network_zone_id,''), COALESCE(ssid,''), COALESCE(vlan,''), COALESCE(ap,''), COALESCE(host(nas_ip),''), COALESCE(auth_session_id,''), identity_conflict, COALESCE(identity_blocker,''), dedupe_key, status, COALESCE(disposition,''), priority, COALESCE(assignee_id,''), risk_score, risk_confidence, assessment_level, COALESCE(ruleset_version,''), due_at, first_seen, last_seen, created_at, updated_at FROM risk_cases`)
	if err != nil {
		return fmt.Errorf("load cases: %w", err)
	}
	for rows.Next() {
		var item RiskCase
		var due sql.NullTime
		var firstSeen, lastSeen, createdAt, updatedAt time.Time
		if err := rows.Scan(&item.CaseID, &item.SubjectType, &item.SubjectID, &item.IP, &item.AccountID, &item.EndpointID, &item.CampusID, &item.Department, &item.PersonType, &item.BuildingID, &item.NetworkZoneID, &item.SSID, &item.VLAN, &item.AP, &item.NASIP, &item.AuthSessionID, &item.IdentityConflict, &item.IdentityBlocker, &item.DedupeKey, &item.Status, &item.Disposition, &item.Priority, &item.AssigneeID, &item.RiskScore, &item.RiskConfidence, &item.AssessmentLevel, &item.RulesetVersion, &due, &firstSeen, &lastSeen, &createdAt, &updatedAt); err != nil {
			rows.Close()
			return err
		}
		item.FirstSeen, item.LastSeen = formatDBTime(firstSeen), formatDBTime(lastSeen)
		item.CreatedAt, item.UpdatedAt = formatDBTime(createdAt), formatDBTime(updatedAt)
		if due.Valid {
			item.DueAt = formatDBTime(due.Time)
		}
		item.Comments = []CaseComment{}
		item.Timeline = []CaseTimeline{}
		doc.Cases[item.CaseID] = item
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT comment_id, case_id, author_id, body, created_at FROM risk_case_comments ORDER BY created_at`)
	if err != nil {
		return fmt.Errorf("load case comments: %w", err)
	}
	for rows.Next() {
		var item CaseComment
		var caseID string
		var createdAt time.Time
		if err := rows.Scan(&item.CommentID, &caseID, &item.AuthorID, &item.Body, &createdAt); err != nil {
			rows.Close()
			return err
		}
		item.CreatedAt = formatDBTime(createdAt)
		caseItem := doc.Cases[caseID]
		caseItem.Comments = append(caseItem.Comments, item)
		doc.Cases[caseID] = caseItem
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT event_id, case_id, actor_id, event_type, COALESCE(before_value,'{}'::jsonb), COALESCE(after_value,'{}'::jsonb), created_at FROM risk_case_timeline ORDER BY created_at`)
	if err != nil {
		return fmt.Errorf("load case timeline: %w", err)
	}
	for rows.Next() {
		var item CaseTimeline
		var caseID string
		var before, after []byte
		var createdAt time.Time
		if err := rows.Scan(&item.EventID, &caseID, &item.ActorID, &item.Type, &before, &after, &createdAt); err != nil {
			rows.Close()
			return err
		}
		_ = json.Unmarshal(before, &item.Before)
		_ = json.Unmarshal(after, &item.After)
		item.CreatedAt = formatDBTime(createdAt)
		caseItem := doc.Cases[caseID]
		caseItem.Timeline = append(caseItem.Timeline, item)
		doc.Cases[caseID] = caseItem
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, `SELECT snapshot_id,case_id,COALESCE(ruleset_version,''),evidence,created_at FROM risk_case_evidence_snapshots ORDER BY case_id, created_at`)
	if err != nil {
		return fmt.Errorf("load case evidence snapshots: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var snapshot CaseEvidenceSnapshot
		var caseID string
		var raw []byte
		var createdAt time.Time
		if err := rows.Scan(&snapshot.SnapshotID, &caseID, &snapshot.RulesetVersion, &raw, &createdAt); err != nil {
			return err
		}
		caseItem := doc.Cases[caseID]
		_ = json.Unmarshal(raw, &snapshot.Evidence)
		snapshot.CreatedAt = formatDBTime(createdAt)
		caseItem.EvidenceHistory = append(caseItem.EvidenceHistory, snapshot)
		if caseItem.EvidenceSnapshot.CaseID == "" {
			caseItem.EvidenceSnapshot = snapshot.Evidence
		}
		doc.Cases[caseID] = caseItem
	}
	return rows.Err()
}

func loadConnectors(ctx context.Context, q operationsQuerier, doc *operationsDocument) error {
	rows, err := q.QueryContext(ctx, `SELECT connector_id, name, endpoint_url, action_mapping, encrypted_secret, mode, enabled, shadow_ready, circuit_open_until, consecutive_failures, shadow_started_at, shadow_validation_since, shadow_candidate_count, shadow_reviewed_count, shadow_accuracy, updated_at FROM enforcement_connectors`)
	if err != nil {
		return fmt.Errorf("load enforcement connectors: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item ActionConnector
		var mapping, secret []byte
		var circuitOpen, shadowStarted, shadowValidationSince sql.NullTime
		var updatedAt time.Time
		if err := rows.Scan(&item.ConnectorID, &item.Name, &item.EndpointURL, &mapping, &secret, &item.Mode, &item.Enabled, &item.ShadowReady, &circuitOpen, &item.ConsecutiveFailures, &shadowStarted, &shadowValidationSince, &item.ShadowCandidateCount, &item.ShadowReviewedCount, &item.ShadowAccuracy, &updatedAt); err != nil {
			return err
		}
		if circuitOpen.Valid {
			item.CircuitOpenUntil = formatDBTime(circuitOpen.Time)
		}
		if shadowStarted.Valid {
			item.ShadowStartedAt = formatDBTime(shadowStarted.Time)
		}
		if shadowValidationSince.Valid {
			item.ShadowValidationSince = formatDBTime(shadowValidationSince.Time)
		}
		_ = json.Unmarshal(mapping, &item.ActionMapping)
		item.EncryptedSecret = string(secret)
		item.UpdatedAt = formatDBTime(updatedAt)
		doc.Connectors[item.ConnectorID] = item
	}
	return rows.Err()
}

func loadActions(ctx context.Context, q operationsQuerier, doc *operationsDocument) error {
	rows, err := q.QueryContext(ctx, `SELECT action_id, idempotency_key, COALESCE(case_id,''), COALESCE(connector_id,''), action_type, subject_type, subject_id, COALESCE(account_id,''), COALESCE(endpoint_id,''), COALESCE(host(ip),''), COALESCE(session_id,''), COALESCE(campus_id,''), status, mode, COALESCE(duration_seconds,0), evidence_ids, COALESCE(ruleset_version,''), COALESCE(remote_action_id,''), retry_count, COALESCE(parent_action_id,''), next_attempt_at, cooldown_until, expires_at, COALESCE(last_error,''), created_by, created_at, updated_at FROM enforcement_actions`)
	if err != nil {
		return fmt.Errorf("load enforcement actions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item EnforcementAction
		var evidenceIDs []byte
		var nextAttempt, cooldown, expires sql.NullTime
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&item.ActionID, &item.IdempotencyKey, &item.CaseID, &item.ConnectorID, &item.ActionType, &item.SubjectType, &item.SubjectID, &item.AccountID, &item.EndpointID, &item.IP, &item.SessionID, &item.CampusID, &item.Status, &item.Mode, &item.DurationSeconds, &evidenceIDs, &item.RulesetVersion, &item.RemoteActionID, &item.RetryCount, &item.ParentActionID, &nextAttempt, &cooldown, &expires, &item.LastError, &item.CreatedBy, &createdAt, &updatedAt); err != nil {
			return err
		}
		_ = json.Unmarshal(evidenceIDs, &item.EvidenceIDs)
		if nextAttempt.Valid {
			item.NextAttemptAt = formatDBTime(nextAttempt.Time)
		}
		if cooldown.Valid {
			item.CooldownUntil = formatDBTime(cooldown.Time)
		}
		if expires.Valid {
			item.ExpiresAt = formatDBTime(expires.Time)
		}
		item.CreatedAt, item.UpdatedAt = formatDBTime(createdAt), formatDBTime(updatedAt)
		doc.Actions[item.ActionID] = item
	}
	return rows.Err()
}

func (s *operationsState) savePostgres(tx *sql.Tx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, item := range s.doc.Campuses {
		_, err := tx.ExecContext(ctx, `INSERT INTO campuses(campus_id,code,name,enabled,updated_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT(campus_id) DO UPDATE SET code=EXCLUDED.code,name=EXCLUDED.name,enabled=EXCLUDED.enabled,updated_at=now()`, item.CampusID, item.Code, item.Name, item.Enabled)
		if err != nil {
			return fmt.Errorf("save campus %s: %w", item.CampusID, err)
		}
	}
	for _, item := range s.doc.Buildings {
		_, err := tx.ExecContext(ctx, `INSERT INTO buildings(building_id,campus_id,code,name,enabled,updated_at) VALUES($1,$2,$3,$4,$5,now()) ON CONFLICT(building_id) DO UPDATE SET campus_id=EXCLUDED.campus_id,code=EXCLUDED.code,name=EXCLUDED.name,enabled=EXCLUDED.enabled,updated_at=now()`, item.BuildingID, item.CampusID, item.Code, item.Name, item.Enabled)
		if err != nil {
			return fmt.Errorf("save building %s: %w", item.BuildingID, err)
		}
	}
	for _, item := range s.doc.NetworkZones {
		cidrs, _ := json.Marshal(item.CIDRs)
		ssids, _ := json.Marshal(item.SSIDs)
		vlans, _ := json.Marshal(item.VLANs)
		_, err := tx.ExecContext(ctx, `INSERT INTO network_zones(network_zone_id,campus_id,building_id,name,cidrs,ssids,vlans,enabled,updated_at) VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,now()) ON CONFLICT(network_zone_id) DO UPDATE SET campus_id=EXCLUDED.campus_id,building_id=EXCLUDED.building_id,name=EXCLUDED.name,cidrs=EXCLUDED.cidrs,ssids=EXCLUDED.ssids,vlans=EXCLUDED.vlans,enabled=EXCLUDED.enabled,updated_at=now()`, item.NetworkZoneID, item.CampusID, item.BuildingID, item.Name, cidrs, ssids, vlans, item.Enabled)
		if err != nil {
			return fmt.Errorf("save network zone %s: %w", item.NetworkZoneID, err)
		}
	}
	for _, item := range s.doc.AccessPoints {
		_, err := tx.ExecContext(ctx, `INSERT INTO access_points(access_point_id,campus_id,building_id,network_zone_id,kind,name,management_ip,enabled,updated_at) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),$5,$6,NULLIF($7,'')::inet,$8,now()) ON CONFLICT(access_point_id) DO UPDATE SET campus_id=EXCLUDED.campus_id,building_id=EXCLUDED.building_id,network_zone_id=EXCLUDED.network_zone_id,kind=EXCLUDED.kind,name=EXCLUDED.name,management_ip=EXCLUDED.management_ip,enabled=EXCLUDED.enabled,updated_at=now()`, item.AccessPointID, item.CampusID, item.BuildingID, item.NetworkZoneID, item.Kind, item.Name, item.ManagementIP, item.Enabled)
		if err != nil {
			return fmt.Errorf("save access point %s: %w", item.AccessPointID, err)
		}
	}
	for _, item := range s.doc.Cases {
		if item.DedupeKey == "" {
			item.DedupeKey = legacyCaseDedupeKey(item.SubjectType, item.SubjectID)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO risk_cases(case_id,subject_type,subject_id,ip,account_id,endpoint_id,campus_id,department,person_type,building_id,network_zone_id,ssid,vlan,ap,nas_ip,auth_session_id,identity_conflict,identity_blocker,dedupe_key,status,disposition,priority,assignee_id,risk_score,risk_confidence,assessment_level,ruleset_version,due_at,first_seen,last_seen,created_at,updated_at) VALUES($1,$2,$3,NULLIF($4,'')::inet,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),NULLIF($12,''),NULLIF($13,''),NULLIF($14,''),NULLIF($15,'')::inet,NULLIF($16,''),$17,NULLIF($18,''),$19,$20,NULLIF($21,''),$22,NULLIF($23,''),$24,$25,$26,NULLIF($27,''),NULLIF($28,'')::timestamptz,$29::timestamptz,$30::timestamptz,$31::timestamptz,$32::timestamptz) ON CONFLICT(case_id) DO UPDATE SET ip=EXCLUDED.ip,account_id=EXCLUDED.account_id,endpoint_id=EXCLUDED.endpoint_id,campus_id=EXCLUDED.campus_id,department=EXCLUDED.department,person_type=EXCLUDED.person_type,building_id=EXCLUDED.building_id,network_zone_id=EXCLUDED.network_zone_id,ssid=EXCLUDED.ssid,vlan=EXCLUDED.vlan,ap=EXCLUDED.ap,nas_ip=EXCLUDED.nas_ip,auth_session_id=EXCLUDED.auth_session_id,identity_conflict=EXCLUDED.identity_conflict,identity_blocker=EXCLUDED.identity_blocker,dedupe_key=EXCLUDED.dedupe_key,status=EXCLUDED.status,disposition=EXCLUDED.disposition,priority=EXCLUDED.priority,assignee_id=EXCLUDED.assignee_id,risk_score=EXCLUDED.risk_score,risk_confidence=EXCLUDED.risk_confidence,assessment_level=EXCLUDED.assessment_level,ruleset_version=EXCLUDED.ruleset_version,due_at=EXCLUDED.due_at,last_seen=EXCLUDED.last_seen,updated_at=EXCLUDED.updated_at`, item.CaseID, item.SubjectType, item.SubjectID, item.IP, item.AccountID, item.EndpointID, item.CampusID, item.Department, item.PersonType, item.BuildingID, item.NetworkZoneID, item.SSID, item.VLAN, item.AP, item.NASIP, item.AuthSessionID, item.IdentityConflict, item.IdentityBlocker, item.DedupeKey, item.Status, item.Disposition, item.Priority, item.AssigneeID, item.RiskScore, item.RiskConfidence, item.AssessmentLevel, item.RulesetVersion, item.DueAt, item.FirstSeen, item.LastSeen, item.CreatedAt, item.UpdatedAt)
		if err != nil {
			return fmt.Errorf("save case %s: %w", item.CaseID, err)
		}
		for _, comment := range item.Comments {
			_, err = tx.ExecContext(ctx, `INSERT INTO risk_case_comments(comment_id,case_id,author_id,body,created_at) VALUES($1,$2,$3,$4,$5::timestamptz) ON CONFLICT(comment_id) DO NOTHING`, comment.CommentID, item.CaseID, comment.AuthorID, comment.Body, comment.CreatedAt)
			if err != nil {
				return fmt.Errorf("save case comment %s: %w", comment.CommentID, err)
			}
		}
		for _, event := range item.Timeline {
			before, _ := json.Marshal(event.Before)
			after, _ := json.Marshal(event.After)
			_, err = tx.ExecContext(ctx, `INSERT INTO risk_case_timeline(event_id,case_id,actor_id,event_type,before_value,after_value,created_at) VALUES($1,$2,$3,$4,$5,$6,$7::timestamptz) ON CONFLICT(event_id) DO NOTHING`, event.EventID, item.CaseID, event.ActorID, event.Type, before, after, event.CreatedAt)
			if err != nil {
				return fmt.Errorf("save case timeline %s: %w", event.EventID, err)
			}
		}
		for _, snapshot := range item.EvidenceHistory {
			evidence, _ := json.Marshal(snapshot.Evidence)
			_, err = tx.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots(snapshot_id,case_id,ruleset_version,evidence,created_at) VALUES($1,$2,NULLIF($3,''),$4,$5::timestamptz) ON CONFLICT(snapshot_id) DO NOTHING`, snapshot.SnapshotID, item.CaseID, snapshot.RulesetVersion, evidence, snapshot.CreatedAt)
			if err != nil {
				return fmt.Errorf("save case evidence %s: %w", snapshot.SnapshotID, err)
			}
		}
	}
	for _, item := range s.doc.Connectors {
		mapping, _ := json.Marshal(item.ActionMapping)
		_, err := tx.ExecContext(ctx, `INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,action_mapping,encrypted_secret,mode,enabled,shadow_ready,circuit_open_until,consecutive_failures,shadow_started_at,shadow_validation_since,shadow_candidate_count,shadow_reviewed_count,shadow_accuracy,updated_by,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::timestamptz,$10,NULLIF($11,'')::timestamptz,NULLIF($12,'')::timestamptz,$13,$14,$15,'system',$16::timestamptz) ON CONFLICT(connector_id) DO UPDATE SET name=EXCLUDED.name,endpoint_url=EXCLUDED.endpoint_url,action_mapping=EXCLUDED.action_mapping,encrypted_secret=EXCLUDED.encrypted_secret,mode=EXCLUDED.mode,enabled=EXCLUDED.enabled,shadow_ready=EXCLUDED.shadow_ready,circuit_open_until=EXCLUDED.circuit_open_until,consecutive_failures=EXCLUDED.consecutive_failures,shadow_started_at=EXCLUDED.shadow_started_at,shadow_validation_since=EXCLUDED.shadow_validation_since,shadow_candidate_count=EXCLUDED.shadow_candidate_count,shadow_reviewed_count=EXCLUDED.shadow_reviewed_count,shadow_accuracy=EXCLUDED.shadow_accuracy,updated_at=EXCLUDED.updated_at`, item.ConnectorID, item.Name, item.EndpointURL, mapping, []byte(item.EncryptedSecret), item.Mode, item.Enabled, item.ShadowReady, item.CircuitOpenUntil, item.ConsecutiveFailures, item.ShadowStartedAt, item.ShadowValidationSince, item.ShadowCandidateCount, item.ShadowReviewedCount, item.ShadowAccuracy, item.UpdatedAt)
		if err != nil {
			return fmt.Errorf("save connector %s: %w", item.ConnectorID, err)
		}
	}
	for _, item := range s.doc.Actions {
		evidenceIDs, _ := json.Marshal(item.EvidenceIDs)
		_, err := tx.ExecContext(ctx, `INSERT INTO enforcement_actions(action_id,idempotency_key,case_id,connector_id,action_type,subject_type,subject_id,account_id,endpoint_id,ip,session_id,campus_id,status,mode,duration_seconds,evidence_ids,ruleset_version,remote_action_id,retry_count,parent_action_id,next_attempt_at,cooldown_until,expires_at,last_error,created_by,created_at,updated_at) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),$5,$6,$7,NULLIF($8,''),NULLIF($9,''),NULLIF($10,'')::inet,NULLIF($11,''),NULLIF($12,''),$13,$14,$15,$16,NULLIF($17,''),NULLIF($18,''),$19,NULLIF($20,''),NULLIF($21,'')::timestamptz,NULLIF($22,'')::timestamptz,NULLIF($23,'')::timestamptz,NULLIF($24,''),$25,$26::timestamptz,$27::timestamptz) ON CONFLICT(action_id) DO UPDATE SET status=EXCLUDED.status,remote_action_id=EXCLUDED.remote_action_id,retry_count=EXCLUDED.retry_count,parent_action_id=EXCLUDED.parent_action_id,next_attempt_at=EXCLUDED.next_attempt_at,cooldown_until=EXCLUDED.cooldown_until,expires_at=EXCLUDED.expires_at,last_error=EXCLUDED.last_error,updated_at=EXCLUDED.updated_at`, item.ActionID, item.IdempotencyKey, item.CaseID, item.ConnectorID, item.ActionType, item.SubjectType, item.SubjectID, item.AccountID, item.EndpointID, item.IP, item.SessionID, item.CampusID, item.Status, item.Mode, item.DurationSeconds, evidenceIDs, item.RulesetVersion, item.RemoteActionID, item.RetryCount, item.ParentActionID, item.NextAttemptAt, item.CooldownUntil, item.ExpiresAt, item.LastError, item.CreatedBy, item.CreatedAt, item.UpdatedAt)
		if err != nil {
			return fmt.Errorf("save enforcement action %s: %w", item.ActionID, err)
		}
	}
	value, _ := json.Marshal(s.doc.GlobalStop)
	_, err := tx.ExecContext(ctx, `INSERT INTO control_plane_settings(setting_key,setting_value,updated_at) VALUES('global_emergency_stop',$1,now()) ON CONFLICT(setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value,updated_at=now()`, value)
	return err
}

func formatDBTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
