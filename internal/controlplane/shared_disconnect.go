package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/srunapi"
	"proxy-sentinel/internal/store"
)

type sharedDisconnectBinding struct {
	GrantID string `json:"grant_id"`
}
type sharedDisconnectPreview struct {
	ReviewID        string                        `json:"review_id"`
	ConnectorID     string                        `json:"connector_id"`
	EvidenceVersion int64                         `json:"evidence_version"`
	IdentityVersion int64                         `json:"identity_version"`
	ConfigVersion   string                        `json:"config_version"`
	Fingerprint     string                        `json:"fingerprint"`
	Ready           bool                          `json:"ready"`
	Blockers        []string                      `json:"blockers"`
	Plan            srunapi.AccountDisconnectPlan `json:"plan"`
}

func sharedDisconnectPath(path string) bool {
	const prefix = "/shared-access/reviews/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	return len(parts) == 2 && parts[0] != "" && (parts[1] == "disconnect-preview" || parts[1] == "disconnect")
}
func (s *Server) managedDisconnectRuntime(ctx context.Context, id string) (NativeActionRuntime, managedIdentityRegistration, error) {
	item, err := s.managedIdentityRegistrationByConnector(ctx, id)
	if err != nil {
		return NativeActionRuntime{}, managedIdentityRegistration{}, err
	}
	if !item.Config.Enabled || item.Config.Kind != "complete_inventory" || item.State != "healthy" || !item.ObservedAt.Valid || item.ObservedAt.Time.After(time.Now()) || time.Since(item.ObservedAt.Time) > 5*time.Second {
		return NativeActionRuntime{}, item, fmt.Errorf("authoritative_inventory_unavailable")
	}
	var hc *http.Client
	if item.Certificate != "" {
		hc, err = srunapi.NewCertificatePinnedClient([]byte(item.Certificate))
		if err != nil {
			return NativeActionRuntime{}, item, err
		}
	}
	client, err := srunapi.New(item.Endpoint, "managed-provider", "managed-provider", hc)
	if err != nil {
		return NativeActionRuntime{}, item, err
	}
	client = client.WithCredentialsProvider(func(c context.Context) (string, string, error) {
		credentials, e := s.credentialsFrom4K(c, id)
		return credentials.AppID, credentials.AppSecret, e
	})
	runtime := NativeActionRuntime{Client: client, CampusID: item.Config.CampusID, AccessDomain: item.Config.AccessDomain, DropType: "radius", Now: time.Now, Read: func(c context.Context) (legacy4k.OnlineInventory, error) {
		next, e := s.managedIdentityRegistrationByConnector(c, id)
		if e != nil {
			return legacy4k.OnlineInventory{}, e
		}
		if next.Version == item.Version && next.Config.Enabled && next.Config.Kind == "complete_inventory" && next.State == "healthy" {
			inventory, e := s.readManagedInventory(c, next)
			if e != nil {
				return inventory, e
			}
			inventory.InstanceID = fmt.Sprintf("4k:%s:config-%d:%s", id, next.Version, inventory.InstanceID)
			return inventory, nil
		}
		return legacy4k.OnlineInventory{}, fmt.Errorf("identity_configuration_changed")
	}}
	return runtime, item, nil
}
func (s *Server) buildSharedDisconnectPreview(ctx context.Context, id string) (sharedDisconnectPreview, error) {
	p := sharedDisconnectPreview{ReviewID: id, Blockers: []string{}, Plan: srunapi.AccountDisconnectPlan{Sessions: []srunapi.PlannedDisconnectSession{}}}
	var account, campus, domain, generation, state string
	var raw []byte
	err := s.operations.db.QueryRowContext(ctx, `SELECT account_id,campus_id,access_domain,session_generation,state,latest_version,latest_result FROM shared_access_reviews WHERE review_id=$1`, id).Scan(&account, &campus, &domain, &generation, &state, &p.EvidenceVersion, &raw)
	if err != nil {
		return p, err
	}
	p.Plan.Account, p.Plan.CampusID, p.Plan.AccessDomain = account, campus, domain
	var result sharedaccess.Result
	if json.Unmarshal(raw, &result) != nil {
		return p, fmt.Errorf("invalid review evidence")
	}
	p.ConfigVersion = result.ConfigVersion
	if account != "yuantong" {
		p.Blockers = append(p.Blockers, "designated_test_account_required")
	}
	if state != "pending" {
		p.Blockers = append(p.Blockers, "review_not_pending")
	}
	if result.ConfigVersion != s.sharedConfig.ID() || result.RuleVersion != sharedaccess.RuleVersion || result.State != "basis_present" {
		p.Blockers = append(p.Blockers, "shared_evidence_not_actionable")
	}
	var conclusion string
	var version int64
	err = s.operations.db.QueryRowContext(ctx, `SELECT conclusion,evidence_version FROM shared_access_review_conclusions WHERE review_id=$1 ORDER BY conclusion_id DESC LIMIT 1`, id).Scan(&conclusion, &version)
	if err != nil && err != sql.ErrNoRows {
		return p, err
	}
	if conclusion != "shared" || version != p.EvidenceVersion {
		p.Blockers = append(p.Blockers, "current_shared_conclusion_required")
	}
	registrations, err := s.managedIdentityRegistrationsByScope(ctx, campus, domain)
	if err != nil {
		return p, err
	}
	for _, item := range registrations {
		if item.Config.CampusID == campus && item.Config.AccessDomain == domain {
			if p.ConnectorID != "" {
				p.Blockers = appendUnique(p.Blockers, "multiple_authorities_require_review")
			} else {
				p.ConnectorID = item.ID
				p.IdentityVersion = item.Version
			}
		}
	}
	if p.ConnectorID == "" {
		p.Blockers = append(p.Blockers, "identity_source_not_configured")
		return p, nil
	}
	doc := emptyOperationsDocument()
	if err = loadConnectorsScoped(ctx, s.operations.db, &doc, " WHERE connector_id=$1", []any{p.ConnectorID}); err != nil {
		return p, err
	}
	if err = loadEmergencyStop(ctx, s.operations.db, &doc); err != nil {
		return p, err
	}
	connector := doc.Connectors[p.ConnectorID]
	if s.readOnly || doc.GlobalStop || !connector.Enabled || connector.ConnectorType != "srun4k" || connector.Mode != "shadow" {
		p.Blockers = append(p.Blockers, "manual_controller_gate_unavailable")
	}
	if until, e := time.Parse(time.RFC3339Nano, connector.CircuitOpenUntil); e == nil && until.After(time.Now()) {
		p.Blockers = append(p.Blockers, "controller_circuit_open")
	}
	runtime, _, err := s.managedDisconnectRuntime(ctx, p.ConnectorID)
	if err != nil {
		p.Blockers = append(p.Blockers, "authoritative_inventory_unavailable")
		return p, nil
	}
	inventory, err := runtime.Read(ctx)
	if err != nil {
		p.Blockers = append(p.Blockers, "authoritative_inventory_query_failed")
		return p, nil
	}
	plan, err := srunapi.PlanAccountDisconnect(inventory, account, campus, domain, time.Now().UTC(), 5*time.Second)
	if err != nil {
		p.Blockers = append(p.Blockers, "current_account_sessions_unavailable")
		return p, nil
	}
	p.Plan = plan
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		p.Blockers = append(p.Blockers, "identity_reader_unavailable")
		return p, nil
	}
	sessions, err := s.policySessionsForScope(ctx, reader, time.Now().UTC(), campus, domain)
	if err != nil {
		return p, err
	}
	if entries, err := s.whitelist.list(ctx); err != nil {
		return p, err
	} else if m := policy.MatchAccountWhitelist(entries, account, sessions, time.Now().UTC()); m != nil {
		p.Blockers = appendUnique(p.Blockers, "whitelist_suppressed")
	}
	if reviewGeneration(result, sessions) != generation {
		p.Blockers = append(p.Blockers, "session_generation_changed")
	}
	windows, err := s.sharedWindows(ctx, time.Now().UTC())
	if err != nil {
		return p, err
	}
	found := false
	for _, w := range windows {
		if w.ID == result.ID {
			evaluation := sharedaccess.Evaluate(w, s.sharedConfig, sessions, time.Now().UTC(), 10*time.Minute)
			if evaluation.State == "basis_present" && evaluation.AccountID == account {
				found = true
			}
			break
		}
	}
	if !found {
		p.Blockers = append(p.Blockers, "shared_evidence_expired_or_coverage_insufficient")
	}
	protected, err := s.sharedDisconnectProtected(ctx, plan, sessions)
	if err != nil {
		return p, err
	}
	if protected {
		p.Blockers = appendUnique(p.Blockers, "manual_exception_applied")
	}
	var cooling bool
	if err = s.operations.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shared_manual_disconnect_grants g JOIN shared_access_reviews r ON r.review_id=g.review_id WHERE g.connector_id=$1 AND r.account_id=$2 AND r.campus_id=$3 AND r.access_domain=$4 AND g.created_at>now()-interval '5 minutes')`, p.ConnectorID, account, campus, domain).Scan(&cooling); err != nil {
		return p, err
	}
	if cooling {
		p.Blockers = append(p.Blockers, "subject_cooldown_active")
	}
	p.Fingerprint = policy.StableID(id, fmt.Sprint(p.EvidenceVersion), p.ConfigVersion, p.ConnectorID, fmt.Sprint(p.IdentityVersion), plan.Fingerprint)
	p.Ready = len(p.Blockers) == 0
	return p, nil
}
func (s *Server) handleSharedDisconnect(w http.ResponseWriter, r *http.Request, ctx context.Context, id string, preview bool) {
	if preview && !sessionHasPermission(sessionFromContext(ctx), "cases:read") {
		writeError(w, 403, "permission_denied", "无权读取复核依据")
		return
	}
	if !preview {
		actor := sessionFromContext(ctx)
		for _, permission := range []string{"integrations:write", "actions:execute", "cases:write"} {
			if !sessionHasPermission(actor, permission) {
				writeError(w, 403, "permission_denied", "人工测试授权权限不足")
				return
			}
		}
	}
	var request struct {
		Fingerprint     string `json:"fingerprint"`
		EvidenceVersion int64  `json:"evidence_version"`
		IdentityVersion int64  `json:"identity_version"`
		ConfigVersion   string `json:"config_version"`
		Authorize       bool   `json:"authorize_designated_test"`
	}
	if !preview {
		d := json.NewDecoder(io.LimitReader(r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&request) != nil {
			writeError(w, 400, "bad_confirmation", "下线确认格式错误")
			return
		}
		var trailing any
		if d.Decode(&trailing) != io.EOF || !request.Authorize || request.Fingerprint == "" {
			writeError(w, 400, "explicit_confirmation_required", "请明确确认本轮指定账号人工测试")
			return
		}
	}
	p, err := s.buildSharedDisconnectPreview(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, 404, "review_not_found", "复核记录不存在")
		} else {
			writeError(w, 503, "disconnect_preview_unavailable", "预览失败；此结果不代表用户离线")
		}
		return
	}
	if preview {
		writeJSON(w, 200, p)
		return
	}
	if !p.Ready {
		writeJSON(w, 409, p)
		return
	}
	if request.Fingerprint != p.Fingerprint || request.EvidenceVersion != p.EvidenceVersion || request.IdentityVersion != p.IdentityVersion || request.ConfigVersion != p.ConfigVersion {
		writeError(w, 409, "confirmation_changed", "依据或会话已变化，请重新预览")
		return
	}
	if err = s.operationCommitGuard(ctx)(); err != nil {
		writeError(w, 409, "task_cancelled", "确认任务已停止")
		return
	}
	guard, _ := ctx.Value(operationTaskCommitKey{}).(*operationTaskCommit)
	var tx *sql.Tx
	owned := guard == nil
	if owned {
		tx, err = s.operations.db.BeginTx(ctx, nil)
		if err != nil {
			writeError(w, 503, "storage_unavailable", "保存确认失败")
			return
		}
		defer tx.Rollback()
	} else {
		tx = guard.tx
	}
	// Lock only the selected connector, identity config and review. Recheck epochs.
	var locked string
	var identityVersion, evidenceVersion int64
	err = tx.QueryRowContext(ctx, `SELECT c.connector_id FROM enforcement_connectors c WHERE c.connector_id=$1 AND c.enabled AND c.mode='shadow' AND c.connector_type='srun4k' FOR UPDATE`, p.ConnectorID).Scan(&locked)
	if err == nil {
		err = tx.QueryRowContext(ctx, `SELECT config_version FROM enforcement_identity_sources WHERE connector_id=$1 FOR UPDATE`, p.ConnectorID).Scan(&identityVersion)
	}
	if err == nil {
		err = tx.QueryRowContext(ctx, `SELECT latest_version FROM shared_access_reviews WHERE review_id=$1 AND state='pending' FOR UPDATE`, id).Scan(&evidenceVersion)
	}
	if err != nil || identityVersion != p.IdentityVersion || evidenceVersion != p.EvidenceVersion {
		writeError(w, 409, "confirmation_changed", "确认配置已变化")
		return
	}
	var concluded int64
	var conclusion string
	if err = tx.QueryRowContext(ctx, `SELECT evidence_version,conclusion FROM shared_access_review_conclusions WHERE review_id=$1 ORDER BY conclusion_id DESC LIMIT 1`, id).Scan(&concluded, &conclusion); err != nil || concluded != p.EvidenceVersion || conclusion != "shared" {
		writeError(w, 409, "confirmation_changed", "人工结论已变化")
		return
	}
	// The connector row serializes competing confirmations; recheck cooldown after locking.
	var cooling bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shared_manual_disconnect_grants g JOIN shared_access_reviews r ON r.review_id=g.review_id WHERE g.connector_id=$1 AND r.account_id=$2 AND r.campus_id=$3 AND r.access_domain=$4 AND g.created_at>now()-interval '5 minutes')`, p.ConnectorID, p.Plan.Account, p.Plan.CampusID, p.Plan.AccessDomain).Scan(&cooling); err != nil {
		writeError(w, 503, "storage_unavailable", "冷却状态读取失败")
		return
	}
	if cooling {
		writeError(w, 409, "subject_cooldown_active", "本账号范围处于五分钟冷却期")
		return
	}
	actor := sessionFromContext(ctx).User.ID
	grantID := "shared-grant-" + shortToken(16)
	if guard != nil {
		grantID = "shared-grant-" + guard.id
	}
	approved, _ := json.Marshal(p.Plan)
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_manual_disconnect_grants(grant_id,review_id,actor_id,connector_id,identity_version,evidence_version,shared_config_version,fingerprint,approved_plan,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '15 minutes') ON CONFLICT(grant_id) DO NOTHING`, grantID, id, actor, p.ConnectorID, p.IdentityVersion, p.EvidenceVersion, p.ConfigVersion, p.Fingerprint, approved)
	doc := emptyOperationsDocument()
	ops := &operationsState{db: s.operations.db, doc: doc, recordBaseline: operationFingerprints(doc)}
	actions := []string{}
	now := formatDBTime(time.Now().UTC())
	for _, target := range p.Plan.Sessions {
		key := policy.StableID(grantID, target.Target.SessionID)
		actionID := "shared-action-" + key
		intent := srunapi.DispatchIntent{Key: key, ConnectorID: p.ConnectorID, Target: target.Target, DropType: "radius"}
		a := EnforcementAction{ActionID: actionID, IdempotencyKey: key, ConnectorID: p.ConnectorID, ActionType: "session.disconnect", SubjectType: "session", SubjectID: target.Target.SessionID, AccountID: p.Plan.Account, SessionID: target.Target.SessionID, CampusID: p.Plan.CampusID, IP: target.Addresses[0], Status: "pending", Mode: "active", EvidenceIDs: []string{id}, CreatedBy: actor, CreatedAt: now, UpdatedAt: now, PolicyParameters: PolicyActionParameters{AccessDomain: p.Plan.AccessDomain, Operation: "disconnect", NativeSelected: true, NativeIntent: &intent, SharedReview: &sharedDisconnectBinding{GrantID: grantID}}}
		ops.doc.Actions[actionID] = a
		actions = append(actions, actionID)
	}
	if err == nil {
		err = ops.savePostgres(tx)
	}
	for _, action := range actions {
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO shared_access_review_executions(review_id,action_id,evidence_version) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, id, action, p.EvidenceVersion)
		}
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'shared_access.disconnect.confirm',$3,'designated account; 15 minute immutable grant',now())`, grantID, actor, id)
	}
	if err == nil && owned {
		err = tx.Commit()
	}
	if err != nil {
		writeError(w, 503, "confirmation_storage_failed", "确认与任务保存失败")
		return
	}
	writeJSON(w, 200, map[string]any{"grant_id": grantID, "action_ids": actions, "status": "pending", "accepted_is_not_offline": true})
}
func (s *Server) validateSharedDisconnectDelivery(ctx context.Context, a EnforcementAction) error {
	if err := s.checkActionWhitelist(ctx, a); err != nil {
		return err
	}
	var review, actor, connector, config string
	var version, evidence int64
	var planRaw []byte
	var expires time.Time
	var revoked bool
	err := s.operations.db.QueryRowContext(ctx, `SELECT review_id,actor_id,connector_id,identity_version,evidence_version,shared_config_version,approved_plan,expires_at,revoked FROM shared_manual_disconnect_grants WHERE grant_id=$1`, a.PolicyParameters.SharedReview.GrantID).Scan(&review, &actor, &connector, &version, &evidence, &config, &planRaw, &expires, &revoked)
	if err != nil || revoked || !expires.After(time.Now()) || a.AccountID != "yuantong" || a.ActionType != "session.disconnect" || a.PolicyParameters.Operation != "disconnect" || connector != a.ConnectorID || actor != a.CreatedBy {
		return fmt.Errorf("manual grant unavailable")
	}
	if s.auth != nil && s.auth.enabled {
		var role string
		var disabled bool
		if s.operations.db.QueryRowContext(ctx, `SELECT role,disabled FROM local_users WHERE user_id=$1`, actor).Scan(&role, &disabled) != nil || disabled {
			return fmt.Errorf("grant actor unavailable")
		}
		session := Session{Permissions: rolePermissions(role)}
		for _, permission := range []string{"integrations:write", "actions:execute", "cases:write"} {
			if !sessionHasPermission(session, permission) {
				return fmt.Errorf("grant permission revoked")
			}
		}
	}
	var latest int64
	var state string
	var raw []byte
	if s.operations.db.QueryRowContext(ctx, `SELECT latest_version,state,latest_result FROM shared_access_reviews WHERE review_id=$1`, review).Scan(&latest, &state, &raw) != nil || latest != evidence || state != "pending" || config != s.sharedConfig.ID() {
		return fmt.Errorf("approved evidence changed")
	}
	var conclusion string
	var concluded int64
	if s.operations.db.QueryRowContext(ctx, `SELECT conclusion,evidence_version FROM shared_access_review_conclusions WHERE review_id=$1 ORDER BY conclusion_id DESC LIMIT 1`, review).Scan(&conclusion, &concluded) != nil || conclusion != "shared" || concluded != evidence {
		return fmt.Errorf("manual conclusion changed")
	}
	runtime, item, err := s.managedDisconnectRuntime(ctx, connector)
	if err != nil || item.Version != version {
		return fmt.Errorf("approved identity changed")
	}
	inventory, err := runtime.Read(ctx)
	if err != nil {
		return err
	}
	var approved srunapi.AccountDisconnectPlan
	if json.Unmarshal(planRaw, &approved) != nil {
		return fmt.Errorf("approved targets invalid")
	}
	if approved.Account != a.AccountID || approved.CampusID != a.CampusID || approved.AccessDomain != a.PolicyParameters.AccessDomain || a.PolicyParameters.NativeIntent == nil {
		return fmt.Errorf("approved scope mismatch")
	}
	targetApproved := false
	for _, old := range approved.Sessions {
		if old.Target == a.PolicyParameters.NativeIntent.Target {
			for _, ip := range old.Addresses {
				if ip == a.IP {
					targetApproved = true
				}
			}
		}
	}
	if !targetApproved {
		return fmt.Errorf("action target not approved")
	}
	current, err := srunapi.PlanAccountDisconnect(inventory, a.AccountID, a.CampusID, a.PolicyParameters.AccessDomain, time.Now().UTC(), 5*time.Second)
	if err != nil {
		return err
	}
	for _, target := range current.Sessions {
		found := false
		for _, old := range approved.Sessions {
			if target.Target == old.Target {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("new or changed session requires confirmation")
		}
	}
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		return fmt.Errorf("identity reader unavailable")
	}
	sessions, err := s.policySessionsForScope(ctx, reader, time.Now().UTC(), a.CampusID, a.PolicyParameters.AccessDomain)
	if err != nil {
		return err
	}
	var result sharedaccess.Result
	if json.Unmarshal(raw, &result) != nil {
		return fmt.Errorf("invalid evidence")
	}
	windows, err := s.sharedWindows(ctx, time.Now().UTC())
	if err != nil {
		return err
	}
	valid := false
	for _, window := range windows {
		if window.ID == result.ID {
			r := sharedaccess.Evaluate(window, s.sharedConfig, sessions, time.Now().UTC(), 10*time.Minute)
			valid = r.State == "basis_present" && r.AccountID == a.AccountID
			break
		}
	}
	if !valid {
		return fmt.Errorf("evidence or coverage no longer valid")
	}
	protected, err := s.sharedDisconnectProtected(ctx, approved, sessions)
	if err != nil || protected {
		return fmt.Errorf("exception gate unavailable")
	}
	return nil
}

// Only authenticated endpoint associations are eligible for endpoint exceptions.
// Neighbor MAC/OUI references never establish a punishment or exemption identity.
func (s *Server) sharedDisconnectProtected(ctx context.Context, plan srunapi.AccountDisconnectPlan, sessions []policy.Session) (bool, error) {
	if s.exceptions == nil {
		return false, fmt.Errorf("exception reader unavailable")
	}
	items, err := s.exceptions.list(ctx, true)
	if err != nil {
		return false, err
	}
	checkDomain := false
	for _, item := range items {
		if item.ScopeType == "domain" && (item.CampusID == "" || item.CampusID == plan.CampusID) {
			checkDomain = true
		}
	}
	for _, target := range plan.Sessions {
		for _, ip := range target.Addresses {
			if matchException(items, ip, plan.Account, "", plan.CampusID) != nil {
				return true, nil
			}
			for _, session := range sessions {
				if session.AccountID == plan.Account && session.CampusID == plan.CampusID && session.AccessDomain == plan.AccessDomain && session.IP == ip && session.EndpointID != "" && session.State(time.Now().UTC()) == "active" && matchException(items, ip, plan.Account, session.EndpointID, plan.CampusID) != nil {
					return true, nil
				}
			}
			if checkDomain {
				evidence, err := s.reader.GetIPEvidence(ctx, ip, 100)
				if err != nil {
					return false, err
				}
				if len(evidence) >= 100 {
					return false, fmt.Errorf("exception evidence may be truncated")
				}
				if matchEvidenceException(items, evidence, plan.CampusID) != nil {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
