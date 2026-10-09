package controlplane

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/productpolicy"
)

type productPolicyState struct {
	key       string
	db        *sql.DB
	decisions chan queuedPolicyDecision
}

func newProductPolicyState(key string, db *sql.DB) *productPolicyState {
	state := &productPolicyState{key: strings.TrimSpace(key), db: db}
	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var table sql.NullString
		if db.QueryRowContext(ctx, `SELECT to_regclass('policy_decision_records')::text`).Scan(&table) == nil && table.Valid {
			state.decisions = make(chan queuedPolicyDecision, 4096)
			go state.runDecisionWriter()
		}
	}
	return state
}

type queuedPolicyDecision struct {
	decisionID     string
	executionID    string
	policyID       string
	policyRevision int
	accountID      string
	known          bool
	violated       bool
	evaluatedAt    time.Time
	document       []byte
}

type productPolicyCoverage struct {
	observedAt time.Time
	products   map[string]bool
}

func (s *productPolicyState) runDecisionWriter() {
	for item := range s.decisions {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err := s.db.ExecContext(ctx, `INSERT INTO policy_decision_records(decision_id,execution_id,policy_id,policy_revision,account_id,known,violated,evaluated_at,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(decision_id) DO NOTHING`, item.decisionID, item.executionID, item.policyID, item.policyRevision, item.accountID, item.known, item.violated, item.evaluatedAt, item.document)
			cancel()
			if err == nil {
				break
			}
			time.Sleep(time.Second)
		}
	}
}

func (s *productPolicyState) coverage(ctx context.Context) (map[string]productPolicyCoverage, error) {
	result := map[string]productPolicyCoverage{}
	if s == nil || s.db == nil {
		return result, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT source,max(observed_at) FROM product_policy_snapshots GROUP BY source`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var source string
		var observed time.Time
		if err = rows.Scan(&source, &observed); err != nil {
			rows.Close()
			return nil, err
		}
		result[source] = productPolicyCoverage{observedAt: observed, products: map[string]bool{}}
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT source,product_id FROM product_catalog WHERE active`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var source, productID string
		if err = rows.Scan(&source, &productID); err != nil {
			return nil, err
		}
		coverage := result[source]
		if coverage.products == nil {
			coverage.products = map[string]bool{}
		}
		coverage.products[productID] = true
		result[source] = coverage
	}
	return result, rows.Err()
}

func constrainProductPolicyInput(definition policy.Definition, input policy.Input, coverage map[string]productPolicyCoverage, coverageErr error, now time.Time) policy.Input {
	if definition.Origin == nil {
		return input
	}
	current, exists := coverage[definition.Origin.Source]
	switch {
	case coverageErr != nil:
		return policy.Input{AccountID: input.AccountID, Reasons: []string{"product_policy_catalog_unavailable"}}
	case !exists || current.observedAt.IsZero() || now.Sub(current.observedAt) > 3*time.Minute:
		return policy.Input{AccountID: input.AccountID, Reasons: []string{"product_policy_snapshot_stale"}}
	case definition.Origin.ExternalProductID != "" && !current.products[definition.Origin.ExternalProductID]:
		return policy.Input{AccountID: input.AccountID, Reasons: []string{"product_missing"}}
	default:
		return input
	}
}

func (s *productPolicyState) authorized(r *http.Request) bool {
	if s == nil || s.key == "" {
		return false
	}
	presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	return presented != "" && hmac.Equal([]byte(presented), []byte(s.key))
}

func (s *Server) handleProductPolicySnapshot(w http.ResponseWriter, r *http.Request) {
	if s.productPolicies == nil || !s.productPolicies.authorized(r) {
		writeError(w, http.StatusUnauthorized, "integration_auth_failed", "valid product-policy integration bearer token required")
		return
	}
	if s.readOnly {
		writeError(w, http.StatusForbidden, "read_only", "product-policy ingestion disabled")
		return
	}
	if s.productPolicies.db == nil {
		writeError(w, http.StatusConflict, "product_policy_storage_unavailable", "product-policy snapshots require database storage")
		return
	}
	snapshotID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if snapshotID == "" || len(snapshotID) > 200 {
		writeError(w, http.StatusBadRequest, "idempotency_key_required", "bounded Idempotency-Key header is required")
		return
	}
	var snapshot productpolicy.Snapshot
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		writeError(w, http.StatusBadRequest, "bad_product_policy_snapshot", err.Error())
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "bad_product_policy_snapshot", "exactly one JSON document required")
		return
	}
	if err := snapshot.NormalizeAndValidate(time.Now().UTC()); err != nil {
		writeError(w, http.StatusBadRequest, "bad_product_policy_snapshot", err.Error())
		return
	}
	created, resolvedID, err := commitProductPolicySnapshot(r.Context(), s.productPolicies.db, snapshotID, snapshot)
	if errors.Is(err, errProductPolicySnapshotConflict) {
		writeError(w, http.StatusConflict, "product_policy_snapshot_conflict", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "product_policy_snapshot_commit_failed", err.Error())
		return
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"snapshot_id": resolvedID, "status": "completed", "replayed": !created, "content_hash": snapshot.ContentHash, "products": len(snapshot.Products), "controls": len(snapshot.Controls)})
}

var errProductPolicySnapshotConflict = errors.New("snapshot identity or observation time already refers to different content")

func commitProductPolicySnapshot(ctx context.Context, db *sql.DB, snapshotID string, snapshot productpolicy.Snapshot) (bool, string, error) {
	document, err := json.Marshal(snapshot)
	if err != nil {
		return false, "", err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, "", err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0)),pg_advisory_xact_lock(hashtextextended($2,0)),pg_advisory_xact_lock(hashtextextended($3,0))`, "product-policy-source:"+snapshot.Source, "product-policy-id:"+snapshot.Source+":"+snapshotID, "product-policy-hash:"+snapshot.Source+":"+snapshot.ContentHash); err != nil {
		return false, "", err
	}
	var existingHash string
	err = tx.QueryRowContext(ctx, `SELECT content_hash FROM product_policy_snapshots WHERE snapshot_id=$1 FOR UPDATE`, snapshotID).Scan(&existingHash)
	if err == nil {
		if existingHash != snapshot.ContentHash {
			return false, "", errProductPolicySnapshotConflict
		}
		return false, snapshotID, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return false, "", err
	}
	var observedID, observedHash string
	err = tx.QueryRowContext(ctx, `SELECT snapshot_id,content_hash FROM product_policy_snapshots WHERE source=$1 AND observed_at=$2`, snapshot.Source, snapshot.ObservedAt).Scan(&observedID, &observedHash)
	if err == nil {
		if observedHash != snapshot.ContentHash {
			return false, "", errProductPolicySnapshotConflict
		}
		return false, observedID, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return false, "", err
	}
	var duplicateID string
	err = tx.QueryRowContext(ctx, `SELECT snapshot_id FROM product_policy_snapshots WHERE source=$1 AND content_hash=$2`, snapshot.Source, snapshot.ContentHash).Scan(&duplicateID)
	if err == nil {
		return false, duplicateID, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return false, "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO product_policy_snapshots(snapshot_id,source,instance_id,observed_at,content_hash,document) VALUES($1,$2,$3,$4,$5,$6)`, snapshotID, snapshot.Source, snapshot.InstanceID, snapshot.ObservedAt, snapshot.ContentHash, document); err != nil {
		return false, "", err
	}
	var newerExists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM product_policy_snapshots WHERE source=$1 AND observed_at>$2)`, snapshot.Source, snapshot.ObservedAt).Scan(&newerExists); err != nil {
		return false, "", err
	}
	if newerExists {
		return true, snapshotID, tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE product_catalog SET active=false,updated_at=now(),snapshot_id=$2 WHERE source=$1`, snapshot.Source, snapshotID); err != nil {
		return false, "", err
	}
	for _, product := range snapshot.Products {
		raw, _ := json.Marshal(product)
		if _, err = tx.ExecContext(ctx, `INSERT INTO product_catalog(source,product_id,name,snapshot_id,document,active) VALUES($1,$2,$3,$4,$5,true) ON CONFLICT(source,product_id) DO UPDATE SET name=EXCLUDED.name,snapshot_id=EXCLUDED.snapshot_id,document=EXCLUDED.document,active=true,updated_at=now()`, snapshot.Source, product.ID, product.Name, snapshotID, raw); err != nil {
			return false, "", err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE product_control_catalog SET active=false,updated_at=now(),snapshot_id=$2 WHERE source=$1`, snapshot.Source, snapshotID); err != nil {
		return false, "", err
	}
	for _, control := range snapshot.Controls {
		raw, _ := json.Marshal(control)
		if _, err = tx.ExecContext(ctx, `INSERT INTO product_control_catalog(source,control_id,name,snapshot_id,document,active) VALUES($1,$2,$3,$4,$5,true) ON CONFLICT(source,control_id) DO UPDATE SET name=EXCLUDED.name,snapshot_id=EXCLUDED.snapshot_id,document=EXCLUDED.document,active=true,updated_at=now()`, snapshot.Source, control.ID, control.Name, snapshotID, raw); err != nil {
			return false, "", err
		}
	}
	return true, snapshotID, tx.Commit()
}

func (s *Server) handleProductPolicyCatalog(w http.ResponseWriter, r *http.Request) {
	if s.productPolicies == nil || s.productPolicies.db == nil {
		writeError(w, http.StatusServiceUnavailable, "product_policy_storage_unavailable", "产品策略目录存储不可用")
		return
	}
	if r.URL.Path != "" && strings.HasSuffix(r.URL.Path, "/status") {
		var products, controls, snapshots int
		var last sql.NullTime
		err := s.productPolicies.db.QueryRowContext(r.Context(), `SELECT (SELECT count(*) FROM product_catalog WHERE active),(SELECT count(*) FROM product_control_catalog WHERE active),(SELECT count(*) FROM product_policy_snapshots),(SELECT max(received_at) FROM product_policy_snapshots)`).Scan(&products, &controls, &snapshots, &last)
		if err != nil {
			writeError(w, 503, "product_policy_status_failed", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"enabled": s.productPolicies.key != "", "active_products": products, "active_controls": controls, "snapshots": snapshots, "last_received_at": nullableTime(last)})
		return
	}
	rows, err := s.productPolicies.db.QueryContext(r.Context(), `SELECT source,product_id,name,snapshot_id,document,active,updated_at FROM product_catalog ORDER BY source,active DESC,name,product_id`)
	if err != nil {
		writeError(w, 503, "product_catalog_failed", err.Error())
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var source, id, name, snapshotID string
		var raw []byte
		var active bool
		var updated time.Time
		if err = rows.Scan(&source, &id, &name, &snapshotID, &raw, &active, &updated); err != nil {
			writeError(w, 503, "product_catalog_failed", err.Error())
			return
		}
		var document any
		_ = json.Unmarshal(raw, &document)
		items = append(items, map[string]any{"source": source, "product_id": id, "name": name, "snapshot_id": snapshotID, "document": document, "active": active, "updated_at": updated})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func nullableTime(value sql.NullTime) any {
	if value.Valid {
		return value.Time.UTC()
	}
	return nil
}

func (s *Server) handlePolicyImports(w http.ResponseWriter, r *http.Request, path string) {
	if s.productPolicies == nil || s.productPolicies.db == nil {
		writeError(w, 503, "policy_import_storage_unavailable", "策略导入存储不可用")
		return
	}
	if path == "/policy-imports/preview" && r.Method == http.MethodPost {
		s.handlePolicyImportPreview(w, r)
		return
	}
	trimmed := strings.TrimPrefix(path, "/policy-imports/")
	if strings.HasSuffix(trimmed, "/publish") && r.Method == http.MethodPost {
		s.handlePolicyImportPublish(w, r, strings.TrimSuffix(trimmed, "/publish"))
		return
	}
	if trimmed != "" && r.Method == http.MethodGet {
		s.handlePolicyImportGet(w, r, trimmed)
		return
	}
	writeError(w, 405, "method_not_allowed", "不支持的策略导入操作")
}

func (s *Server) handlePolicyImportPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Source     string `json:"source"`
		SnapshotID string `json:"snapshot_id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(w, 400, "bad_policy_import", err.Error())
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, 400, "bad_policy_import", "请求体只能包含一个 JSON 对象")
		return
	}
	var snapshotID string
	var raw []byte
	var err error
	if strings.TrimSpace(body.SnapshotID) != "" {
		err = s.productPolicies.db.QueryRowContext(r.Context(), `SELECT snapshot_id,document FROM product_policy_snapshots WHERE snapshot_id=$1`, strings.TrimSpace(body.SnapshotID)).Scan(&snapshotID, &raw)
	} else {
		err = s.productPolicies.db.QueryRowContext(r.Context(), `SELECT snapshot_id,document FROM product_policy_snapshots WHERE source=$1 ORDER BY observed_at DESC,received_at DESC LIMIT 1`, strings.TrimSpace(body.Source)).Scan(&snapshotID, &raw)
	}
	if err == sql.ErrNoRows {
		writeError(w, 404, "product_policy_snapshot_not_found", "产品策略快照不存在")
		return
	}
	if err != nil {
		writeError(w, 503, "policy_import_preview_failed", err.Error())
		return
	}
	var snapshot productpolicy.Snapshot
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		writeError(w, 503, "policy_import_preview_failed", err.Error())
		return
	}
	batchID := "policy-import-" + policy.StableID(snapshotID, time.Now().UTC().String())
	preview := productpolicy.BuildPreview(snapshot, snapshotID, batchID, time.Now().UTC())
	previewRaw, _ := json.Marshal(preview)
	actor := sessionFromContext(r.Context()).User.ID
	if _, err = s.productPolicies.db.ExecContext(r.Context(), `INSERT INTO policy_import_batches(batch_id,source,snapshot_id,status,preview,created_by) VALUES($1,$2,$3,'previewed',$4,$5)`, batchID, snapshot.Source, snapshotID, previewRaw, actor); err != nil {
		writeError(w, 503, "policy_import_preview_failed", err.Error())
		return
	}
	s.appendAudit(r.Context(), "policy-imports.preview", batchID, "success")
	writeJSON(w, 201, map[string]any{"batch_id": batchID, "status": "previewed", "preview": preview})
}

func (s *Server) handlePolicyImportGet(w http.ResponseWriter, r *http.Request, batchID string) {
	var source, snapshotID, status, createdBy string
	var preview []byte
	var createdAt time.Time
	var publishedAt sql.NullTime
	err := s.productPolicies.db.QueryRowContext(r.Context(), `SELECT source,snapshot_id,status,preview,created_by,created_at,published_at FROM policy_import_batches WHERE batch_id=$1`, batchID).Scan(&source, &snapshotID, &status, &preview, &createdBy, &createdAt, &publishedAt)
	if err == sql.ErrNoRows {
		writeError(w, 404, "policy_import_not_found", "策略导入批次不存在")
		return
	}
	if err != nil {
		writeError(w, 503, "policy_import_read_failed", err.Error())
		return
	}
	var document any
	_ = json.Unmarshal(preview, &document)
	writeJSON(w, 200, map[string]any{"batch_id": batchID, "source": source, "snapshot_id": snapshotID, "status": status, "preview": document, "created_by": createdBy, "created_at": createdAt, "published_at": nullableTime(publishedAt)})
}

func (s *Server) handlePolicyImportPublish(w http.ResponseWriter, r *http.Request, batchID string) {
	policies, replayed, err := publishPolicyImport(r.Context(), s.productPolicies.db, batchID)
	if errors.Is(err, errPolicyImportNotFound) {
		writeError(w, 404, "policy_import_not_found", "策略导入批次不存在")
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, errPolicyImportInvalid):
			writeError(w, 409, "policy_import_invalid", err.Error())
		case errors.Is(err, errPolicyImportConflict):
			writeError(w, 409, "policy_import_conflict", err.Error())
		default:
			writeError(w, 503, "policy_import_publish_failed", err.Error())
		}
		return
	}
	s.appendAudit(r.Context(), "policy-imports.publish", batchID, "success")
	writeJSON(w, 200, map[string]any{"batch_id": batchID, "status": "published", "policies": policies, "replayed": replayed})
}

var (
	errPolicyImportNotFound = errors.New("policy import batch not found")
	errPolicyImportInvalid  = errors.New("policy import contains an invalid policy")
	errPolicyImportConflict = errors.New("stable policy id is occupied by another source")
)

func publishPolicyImport(ctx context.Context, db *sql.DB, batchID string) ([]policy.Definition, bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	var status string
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT status,preview FROM policy_import_batches WHERE batch_id=$1 FOR UPDATE`, batchID).Scan(&status, &raw)
	if err == sql.ErrNoRows {
		return nil, false, errPolicyImportNotFound
	}
	if err != nil {
		return nil, false, err
	}
	if status == "published" {
		return []policy.Definition{}, true, tx.Commit()
	}
	var preview productpolicy.Preview
	if err = json.Unmarshal(raw, &preview); err != nil {
		return nil, false, err
	}
	policies := []policy.Definition{}
	for _, item := range preview.Items {
		if item.Disposition != "direct" || item.Policy == nil {
			continue
		}
		p := *item.Policy
		p.Enabled = true
		p.Mode = "observe"
		if err = p.Validate(); err != nil {
			return nil, false, fmt.Errorf("%w: %v", errPolicyImportInvalid, err)
		}
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "policy-definition:"+p.ID); err != nil {
			return nil, false, err
		}
		var oldRaw []byte
		err = tx.QueryRowContext(ctx, `SELECT document FROM account_policy_definitions WHERE id=$1 FOR UPDATE`, p.ID).Scan(&oldRaw)
		if err == nil {
			var old policy.Definition
			if json.Unmarshal(oldRaw, &old) != nil || old.Origin == nil || old.Origin.Source != p.Origin.Source {
				return nil, false, errPolicyImportConflict
			}
			p.Revision = old.Revision + 1
		} else if err == sql.ErrNoRows {
			p.Revision = 1
		} else {
			return nil, false, err
		}
		policyRaw, _ := json.Marshal(p)
		if _, err = tx.ExecContext(ctx, `INSERT INTO account_policy_definitions(id,document,updated_at) VALUES($1,$2,now()) ON CONFLICT(id) DO UPDATE SET document=EXCLUDED.document,updated_at=now()`, p.ID, policyRaw); err != nil {
			return nil, false, err
		}
		policies = append(policies, p)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE policy_import_batches SET status='published',published_at=now() WHERE batch_id=$1`, batchID); err != nil {
		return nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	return policies, false, nil
}

func (s *Server) handlePolicyDecisionRecords(w http.ResponseWriter, r *http.Request) {
	if s.productPolicies == nil || s.productPolicies.db == nil {
		writeJSON(w, 200, map[string]any{"items": []any{}})
		return
	}
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, 400, "bad_limit", err.Error())
		return
	}
	rows, err := s.productPolicies.db.QueryContext(r.Context(), `SELECT document FROM policy_decision_records WHERE ($1='' OR account_id=$1) AND ($2='' OR policy_id=$2) ORDER BY evaluated_at DESC,decision_id LIMIT $3`, r.URL.Query().Get("account_id"), r.URL.Query().Get("policy_id"), limit)
	if err != nil {
		writeError(w, 503, "policy_decisions_failed", err.Error())
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			writeError(w, 503, "policy_decisions_failed", err.Error())
			return
		}
		var item any
		_ = json.Unmarshal(raw, &item)
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) appendPolicyDecision(ctx context.Context, p policy.Definition, e policy.Execution, in policy.Input, now time.Time, sessions []policy.Session) {
	if s.productPolicies == nil || s.productPolicies.decisions == nil {
		return
	}
	productIDs, groupIDs := map[string]bool{}, map[string]bool{}
	identitySnapshotIDs := map[string]bool{}
	bindings := []string{}
	for _, session := range sessions {
		if session.AccountID != in.AccountID || !sessionMatchesPolicyStatic(p.Scope, session) || session.State(now) == "absent" || session.State(now) == "ended" {
			continue
		}
		if session.ProductID != "" {
			productIDs[session.ProductID] = true
		}
		if session.GroupID != "" {
			groupIDs[session.GroupID] = true
		}
		for _, snapshotID := range session.IdentitySnapshotIDs {
			if snapshotID != "" {
				identitySnapshotIDs[snapshotID] = true
			}
		}
		bindings = append(bindings, session.ID+"@"+session.StartedAt.UTC().Format(time.RFC3339Nano))
	}
	products, groups := mapKeys(productIDs), mapKeys(groupIDs)
	sort.Strings(bindings)
	identitySnapshots := mapKeys(identitySnapshotIDs)
	decisionID := policy.StableID(p.ID, fmt.Sprint(p.Revision), in.AccountID, fmt.Sprint(e.Episode), fmt.Sprint(in.Known), fmt.Sprint(in.Violated), strings.Join(in.Reasons, ","), strings.Join(bindings, ","), strings.Join(identitySnapshots, ","))
	document := map[string]any{"decision_id": decisionID, "execution_id": e.ID, "policy_id": p.ID, "policy_revision": p.Revision, "account_id": in.AccountID, "known": in.Known, "violated": in.Known && in.Violated, "evaluated_at": now, "product_ids": products, "group_ids": groups, "identity_snapshot_ids": identitySnapshots, "session_bindings": bindings, "session_count": in.SessionCount, "device_count": in.DeviceCount, "mobile_count": in.MobileCount, "pc_count": in.PCCount, "coverage_complete": in.CoverageComplete, "reasons": in.Reasons, "evidence_ids": in.EvidenceIDs, "planned_stages": p.Stages, "execution_state": e.State, "origin": p.Origin}
	raw, _ := json.Marshal(document)
	item := queuedPolicyDecision{decisionID: decisionID, executionID: e.ID, policyID: p.ID, policyRevision: p.Revision, accountID: in.AccountID, known: in.Known, violated: in.Known && in.Violated, evaluatedAt: now, document: raw}
	select {
	case s.productPolicies.decisions <- item:
	case <-ctx.Done():
	}
}

func sessionMatchesPolicyStatic(scope policy.Scope, session policy.Session) bool {
	contains := func(values []string, value string) bool {
		if len(values) == 0 {
			return true
		}
		for _, candidate := range values {
			if candidate == value {
				return true
			}
		}
		return false
	}
	return contains(scope.Accounts, session.AccountID) && contains(scope.Groups, session.GroupID) && contains(scope.Products, session.ProductID) && contains(scope.Campuses, session.CampusID) && contains(scope.VLANs, session.VLAN)
}

func mapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
