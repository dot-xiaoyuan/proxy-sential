package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	maxAssetLedgerEntriesPerImport = 20000
	maxAssetReconcileItemsPerGroup = 200
)

// AssetManualAnnotation 表示对单台发现设备或三层受管网元的人工核验、纠偏与资产备注。
type AssetManualAnnotation struct {
	TargetKey          string `json:"target_key"`
	SensorID           string `json:"sensor_id,omitempty"`
	VerificationStatus string `json:"verification_status"`
	OverrideDeviceType string `json:"override_device_type,omitempty"`
	OverrideBrand      string `json:"override_brand,omitempty"`
	OverrideModel      string `json:"override_model,omitempty"`
	Department         string `json:"department,omitempty"`
	OwnerName          string `json:"owner_name,omitempty"`
	AssetTag           string `json:"asset_tag,omitempty"`
	Note               string `json:"note,omitempty"`
	UpdatedBy          string `json:"updated_by,omitempty"`
	CreatedAt          string `json:"created_at,omitempty"`
	UpdatedAt          string `json:"updated_at,omitempty"`
}

// AssetLedgerSnapshot 表示一份已持久化导入的校方资产台账快照。
type AssetLedgerSnapshot struct {
	LedgerID   string `json:"ledger_id"`
	SensorID   string `json:"sensor_id,omitempty"`
	Name       string `json:"name"`
	SourceKind string `json:"source_kind"`
	EntryCount int    `json:"entry_count"`
	ImportedBy string `json:"imported_by,omitempty"`
	ImportedAt string `json:"imported_at"`
	Note       string `json:"note,omitempty"`
}

// AssetLedgerEntry 表示校方台账中的一条设备登记记录。
type AssetLedgerEntry struct {
	MAC            string `json:"mac,omitempty"`
	IP             string `json:"ip,omitempty"`
	AssetName      string `json:"asset_name,omitempty"`
	ExpectedType   string `json:"expected_type,omitempty"`
	ExpectedVendor string `json:"expected_vendor,omitempty"`
	ExpectedModel  string `json:"expected_model,omitempty"`
	Department     string `json:"department,omitempty"`
	Location       string `json:"location,omitempty"`
	AssetTag       string `json:"asset_tag,omitempty"`
}

// AssetReconcileObserved 表示被动发现层观察到的一台当前活跃设备或三层受管网元摘要。
type AssetReconcileObserved struct {
	Key          string `json:"key"`
	MAC          string `json:"mac,omitempty"`
	IP           string `json:"ip,omitempty"`
	ObservedType string `json:"observed_type,omitempty"`
	Vendor       string `json:"vendor,omitempty"`
	LastSeen     string `json:"last_seen,omitempty"`
	IdentityKind string `json:"identity_kind,omitempty"`
}

// AssetReconcileItem 表示四象限对账明细条目。
type AssetReconcileItem struct {
	Status         string `json:"status"`
	MAC            string `json:"mac,omitempty"`
	IP             string `json:"ip,omitempty"`
	AssetName      string `json:"asset_name,omitempty"`
	AssetTag       string `json:"asset_tag,omitempty"`
	Department     string `json:"department,omitempty"`
	Location       string `json:"location,omitempty"`
	ExpectedType   string `json:"expected_type,omitempty"`
	ObservedType   string `json:"observed_type,omitempty"`
	ExpectedVendor string `json:"expected_vendor,omitempty"`
	ObservedVendor string `json:"observed_vendor,omitempty"`
	LastSeen       string `json:"last_seen,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

// AssetLedgerReconcileSummary 汇总四象限对账计数。
type AssetLedgerReconcileSummary struct {
	LedgerTotal            int `json:"ledger_total"`
	ObservedTotal          int `json:"observed_total"`
	RegisteredActive       int `json:"registered_active"`
	DiscoveredUnregistered int `json:"discovered_unregistered"`
	LedgerOffline          int `json:"ledger_offline"`
	AttributeMismatch      int `json:"attribute_mismatch"`
}

// AssetLedgerReconcileResponse 是持久化台账与实时被动发现对账的完整响应。
type AssetLedgerReconcileResponse struct {
	Ledger       AssetLedgerSnapshot         `json:"ledger"`
	Window       string                      `json:"window"`
	ReconciledAt string                      `json:"reconciled_at"`
	Summary      AssetLedgerReconcileSummary `json:"summary"`
	Items        []AssetReconcileItem        `json:"items"`
	Truncated    bool                        `json:"truncated"`
}

func (s *Server) assetGovernanceWritable() bool {
	if !s.readOnly {
		return true
	}
	return s.assetAnnotationsWrite || os.Getenv("PROXY_SENTINEL_ASSET_ANNOTATIONS_WRITE") == "true"
}

func (s *Server) assetGovernanceMutationAllowed(method, path string) bool {
	if !s.assetGovernanceWritable() {
		return false
	}
	if path == "/discovery/annotations" && (method == http.MethodPut || method == http.MethodDelete) {
		return true
	}
	if path == "/discovery/ledgers" && method == http.MethodPost {
		return true
	}
	if strings.HasPrefix(path, "/discovery/ledgers/") && method == http.MethodDelete {
		return true
	}
	return false
}

func normalizeAssetTargetKey(raw string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" || len(v) > 128 {
		return "", false
	}
	if strings.HasPrefix(v, "mac:") {
		hw, err := net.ParseMAC(strings.TrimPrefix(v, "mac:"))
		if err != nil {
			return "", false
		}
		return "mac:" + strings.ToLower(hw.String()), true
	}
	if strings.HasPrefix(v, "ip:") {
		ip := net.ParseIP(strings.TrimPrefix(v, "ip:"))
		if ip == nil {
			return "", false
		}
		return "ip:" + ip.String(), true
	}
	if hw, err := net.ParseMAC(v); err == nil {
		return "mac:" + strings.ToLower(hw.String()), true
	}
	if ip := net.ParseIP(v); ip != nil {
		return "ip:" + ip.String(), true
	}
	return "", false
}

func normalizeLedgerMAC(raw string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(hw.String())
}

func normalizeLedgerIP(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func trimBounded(raw string, maxLen int) string {
	clean := strings.TrimSpace(raw)
	runes := []rune(clean)
	if len(runes) > maxLen {
		return string(runes[:maxLen])
	}
	return clean
}

func randomGovernanceID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}

func (s *Server) actorName(r *http.Request) string {
	session := sessionFromContext(r.Context())
	if name := strings.TrimSpace(session.User.Name); name != "" {
		return name
	}
	if id := strings.TrimSpace(session.User.ID); id != "" {
		return id
	}
	return "operator"
}

func (s *Server) writeGovernanceAudit(ctx context.Context, db *sql.DB, actor, action, target, outcome string) {
	if db == nil {
		return
	}
	_, _ = db.ExecContext(ctx,
		`INSERT INTO audit_logs(audit_id, actor, action, target, outcome, created_at) VALUES($1,$2,$3,$4,$5,now())`,
		randomGovernanceID("audit"), actor, action, trimBounded(target, 200), trimBounded(outcome, 120))
}

func (s *Server) handleAssetGovernance(w http.ResponseWriter, r *http.Request, path string) {
	if s.operations == nil || s.operations.db == nil {
		writeError(w, http.StatusServiceUnavailable, "discovery_storage", "资产运营治理需要 PostgreSQL")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	db := s.operations.db

	switch {
	case path == "/discovery/annotations" && r.Method == http.MethodGet:
		s.handleListAssetAnnotations(ctx, db, w, r)
	case path == "/discovery/annotations" && r.Method == http.MethodPut:
		if !s.assetGovernanceWritable() {
			writeError(w, http.StatusForbidden, "read_only", "当前未开启资产人工标注写入权限")
			return
		}
		s.handleUpsertAssetAnnotation(ctx, db, w, r)
	case path == "/discovery/annotations" && r.Method == http.MethodDelete:
		if !s.assetGovernanceWritable() {
			writeError(w, http.StatusForbidden, "read_only", "当前未开启资产人工标注写入权限")
			return
		}
		s.handleDeleteAssetAnnotation(ctx, db, w, r)
	case path == "/discovery/ledgers" && r.Method == http.MethodGet:
		s.handleListAssetLedgers(ctx, db, w, r)
	case path == "/discovery/ledgers" && r.Method == http.MethodPost:
		if !s.assetGovernanceWritable() {
			writeError(w, http.StatusForbidden, "read_only", "当前未开启校方台账导入写入权限")
			return
		}
		s.handleCreateAssetLedger(ctx, db, w, r)
	case strings.HasPrefix(path, "/discovery/ledgers/") && strings.HasSuffix(path, "/reconcile") && r.Method == http.MethodGet:
		ledgerID := strings.TrimSuffix(strings.TrimPrefix(path, "/discovery/ledgers/"), "/reconcile")
		s.handleReconcileAssetLedger(ctx, db, w, r, strings.Trim(ledgerID, "/"))
	case strings.HasPrefix(path, "/discovery/ledgers/") && r.Method == http.MethodDelete:
		if !s.assetGovernanceWritable() {
			writeError(w, http.StatusForbidden, "read_only", "当前未开启校方台账管理写入权限")
			return
		}
		ledgerID := strings.Trim(strings.TrimPrefix(path, "/discovery/ledgers/"), "/")
		s.handleDeleteAssetLedger(ctx, db, w, r, ledgerID)
	default:
		writeError(w, http.StatusNotFound, "not_found", "未找到资产运营接口")
	}
}

func (s *Server) handleListAssetAnnotations(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request) {
	targetParam := strings.TrimSpace(r.URL.Query().Get("target_key"))
	var rows *sql.Rows
	var err error
	if targetParam != "" {
		normalizedKey, ok := normalizeAssetTargetKey(targetParam)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad_target_key", "无效的设备标识（需为 MAC 或 IP）")
			return
		}
		rows, err = db.QueryContext(ctx, `
SELECT target_key, sensor_id, verification_status, override_device_type, override_brand, override_model,
       department, owner_name, asset_tag, note, updated_by, created_at, updated_at
FROM asset_manual_annotations
WHERE target_key = $1`, normalizedKey)
	} else {
		rows, err = db.QueryContext(ctx, `
SELECT target_key, sensor_id, verification_status, override_device_type, override_brand, override_model,
       department, owner_name, asset_tag, note, updated_by, created_at, updated_at
FROM asset_manual_annotations
ORDER BY updated_at DESC
LIMIT 200`)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "annotation_read_failed", err.Error())
		return
	}
	defer rows.Close()
	items := []AssetManualAnnotation{}
	for rows.Next() {
		var item AssetManualAnnotation
		var createdAt, updatedAt time.Time
		if scanErr := rows.Scan(
			&item.TargetKey, &item.SensorID, &item.VerificationStatus, &item.OverrideDeviceType,
			&item.OverrideBrand, &item.OverrideModel, &item.Department, &item.OwnerName,
			&item.AssetTag, &item.Note, &item.UpdatedBy, &createdAt, &updatedAt,
		); scanErr != nil {
			writeError(w, http.StatusInternalServerError, "annotation_scan_failed", scanErr.Error())
			return
		}
		item.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		item.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"writable": s.assetGovernanceWritable(),
		"items":    items,
	})
}

func (s *Server) handleUpsertAssetAnnotation(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var body AssetManualAnnotation
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "请求体 JSON 格式错误")
		return
	}
	key, ok := normalizeAssetTargetKey(body.TargetKey)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_target_key", "target_key 必须为有效 MAC 或 IP")
		return
	}
	status := strings.TrimSpace(body.VerificationStatus)
	if status == "" {
		status = "verified"
	}
	switch status {
	case "verified", "corrected", "ignored", "unverified":
	default:
		writeError(w, http.StatusBadRequest, "bad_status", "不支持的核验状态")
		return
	}
	actor := s.actorName(r)
	sensorID := trimBounded(body.SensorID, 64)
	if sensorID == "" {
		sensorID = s.sensorID
	}
	item := AssetManualAnnotation{
		TargetKey:          key,
		SensorID:           sensorID,
		VerificationStatus: status,
		OverrideDeviceType: trimBounded(body.OverrideDeviceType, 64),
		OverrideBrand:      trimBounded(body.OverrideBrand, 64),
		OverrideModel:      trimBounded(body.OverrideModel, 96),
		Department:         trimBounded(body.Department, 96),
		OwnerName:          trimBounded(body.OwnerName, 64),
		AssetTag:           trimBounded(body.AssetTag, 64),
		Note:               trimBounded(body.Note, 512),
		UpdatedBy:          actor,
	}
	var createdAt, updatedAt time.Time
	err := db.QueryRowContext(ctx, `
INSERT INTO asset_manual_annotations(
  target_key, sensor_id, verification_status, override_device_type, override_brand, override_model,
  department, owner_name, asset_tag, note, updated_by, created_at, updated_at
) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now(),now())
ON CONFLICT(target_key) DO UPDATE SET
  sensor_id = EXCLUDED.sensor_id,
  verification_status = EXCLUDED.verification_status,
  override_device_type = EXCLUDED.override_device_type,
  override_brand = EXCLUDED.override_brand,
  override_model = EXCLUDED.override_model,
  department = EXCLUDED.department,
  owner_name = EXCLUDED.owner_name,
  asset_tag = EXCLUDED.asset_tag,
  note = EXCLUDED.note,
  updated_by = EXCLUDED.updated_by,
  updated_at = now()
RETURNING created_at, updated_at`,
		item.TargetKey, item.SensorID, item.VerificationStatus, item.OverrideDeviceType,
		item.OverrideBrand, item.OverrideModel, item.Department, item.OwnerName,
		item.AssetTag, item.Note, item.UpdatedBy,
	).Scan(&createdAt, &updatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "annotation_write_failed", err.Error())
		return
	}
	item.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	item.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	s.writeGovernanceAudit(ctx, db, actor, "asset.annotation.upsert", item.TargetKey, item.VerificationStatus)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleDeleteAssetAnnotation(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request) {
	key, ok := normalizeAssetTargetKey(r.URL.Query().Get("target_key"))
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_target_key", "target_key 必须为有效 MAC 或 IP")
		return
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM asset_manual_annotations WHERE target_key = $1`, key); err != nil {
		writeError(w, http.StatusInternalServerError, "annotation_delete_failed", err.Error())
		return
	}
	s.writeGovernanceAudit(ctx, db, s.actorName(r), "asset.annotation.delete", key, "deleted")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "target_key": key})
}

func (s *Server) handleListAssetLedgers(ctx context.Context, db *sql.DB, w http.ResponseWriter, _ *http.Request) {
	rows, err := db.QueryContext(ctx, `
SELECT ledger_id, sensor_id, name, source_kind, entry_count, imported_by, imported_at, note
FROM asset_ledger_snapshots
ORDER BY imported_at DESC
LIMIT 50`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ledger_list_failed", err.Error())
		return
	}
	defer rows.Close()
	items := []AssetLedgerSnapshot{}
	for rows.Next() {
		var item AssetLedgerSnapshot
		var importedAt time.Time
		if scanErr := rows.Scan(
			&item.LedgerID, &item.SensorID, &item.Name, &item.SourceKind,
			&item.EntryCount, &item.ImportedBy, &importedAt, &item.Note,
		); scanErr != nil {
			writeError(w, http.StatusInternalServerError, "ledger_scan_failed", scanErr.Error())
			return
		}
		item.ImportedAt = importedAt.UTC().Format(time.RFC3339)
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"writable": s.assetGovernanceWritable(),
		"items":    items,
	})
}

func (s *Server) handleCreateAssetLedger(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string             `json:"name"`
		SourceKind string             `json:"source_kind"`
		Note       string             `json:"note"`
		Entries    []AssetLedgerEntry `json:"entries"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "台账请求体解析失败")
		return
	}
	name := trimBounded(req.Name, 128)
	if name == "" {
		writeError(w, http.StatusBadRequest, "bad_name", "请填写台账名称")
		return
	}
	if len(req.Entries) == 0 || len(req.Entries) > maxAssetLedgerEntriesPerImport {
		writeError(w, http.StatusBadRequest, "bad_entries", fmt.Sprintf("台账记录条数需在 1～%d 之间", maxAssetLedgerEntriesPerImport))
		return
	}
	sourceKind := trimBounded(req.SourceKind, 32)
	if sourceKind == "" {
		sourceKind = "general"
	}
	validEntries := make([]AssetLedgerEntry, 0, len(req.Entries))
	for _, entry := range req.Entries {
		mac := normalizeLedgerMAC(entry.MAC)
		ip := normalizeLedgerIP(entry.IP)
		if mac == "" && ip == "" {
			continue
		}
		validEntries = append(validEntries, AssetLedgerEntry{
			MAC:            mac,
			IP:             ip,
			AssetName:      trimBounded(entry.AssetName, 128),
			ExpectedType:   strings.ToLower(trimBounded(entry.ExpectedType, 64)),
			ExpectedVendor: trimBounded(entry.ExpectedVendor, 64),
			ExpectedModel:  trimBounded(entry.ExpectedModel, 96),
			Department:     trimBounded(entry.Department, 96),
			Location:       trimBounded(entry.Location, 128),
			AssetTag:       trimBounded(entry.AssetTag, 64),
		})
	}
	if len(validEntries) == 0 {
		writeError(w, http.StatusBadRequest, "empty_valid_entries", "台账中没有包含有效 MAC 或 IP 的记录")
		return
	}
	actor := s.actorName(r)
	ledger := AssetLedgerSnapshot{
		LedgerID:   randomGovernanceID("ledger"),
		SensorID:   s.sensorID,
		Name:       name,
		SourceKind: sourceKind,
		EntryCount: len(validEntries),
		ImportedBy: actor,
		Note:       trimBounded(req.Note, 512),
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ledger_tx_failed", err.Error())
		return
	}
	defer tx.Rollback()
	var importedAt time.Time
	if err := tx.QueryRowContext(ctx, `
INSERT INTO asset_ledger_snapshots(ledger_id, sensor_id, name, source_kind, entry_count, imported_by, imported_at, note)
VALUES($1,$2,$3,$4,$5,$6,now(),$7)
RETURNING imported_at`,
		ledger.LedgerID, ledger.SensorID, ledger.Name, ledger.SourceKind, ledger.EntryCount, ledger.ImportedBy, ledger.Note,
	).Scan(&importedAt); err != nil {
		writeError(w, http.StatusInternalServerError, "ledger_insert_failed", err.Error())
		return
	}
	entriesJSON, _ := json.Marshal(validEntries)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO asset_ledger_entries(ledger_id, mac, ip, asset_name, expected_type, expected_vendor, expected_model, department, location, asset_tag)
SELECT $1, r.mac, r.ip, r.asset_name, r.expected_type, r.expected_vendor, r.expected_model, r.department, r.location, r.asset_tag
FROM jsonb_to_recordset($2::jsonb) AS r(
  mac text, ip text, asset_name text, expected_type text, expected_vendor text,
  expected_model text, department text, location text, asset_tag text
)`, ledger.LedgerID, string(entriesJSON)); err != nil {
		writeError(w, http.StatusInternalServerError, "ledger_entries_insert_failed", err.Error())
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "ledger_commit_failed", err.Error())
		return
	}
	ledger.ImportedAt = importedAt.UTC().Format(time.RFC3339)
	s.writeGovernanceAudit(ctx, db, actor, "asset.ledger.import", ledger.LedgerID+":"+ledger.Name, fmt.Sprintf("entries=%d", ledger.EntryCount))
	writeJSON(w, http.StatusCreated, ledger)
}

func (s *Server) handleDeleteAssetLedger(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request, ledgerID string) {
	if ledgerID == "" {
		writeError(w, http.StatusBadRequest, "bad_ledger_id", "缺少台账 ID")
		return
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM asset_ledger_snapshots WHERE ledger_id = $1`, ledgerID); err != nil {
		writeError(w, http.StatusInternalServerError, "ledger_delete_failed", err.Error())
		return
	}
	s.writeGovernanceAudit(ctx, db, s.actorName(r), "asset.ledger.delete", ledgerID, "deleted")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "ledger_id": ledgerID})
}

func (s *Server) handleReconcileAssetLedger(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request, ledgerID string) {
	if ledgerID == "" {
		writeError(w, http.StatusBadRequest, "bad_ledger_id", "缺少台账 ID")
		return
	}
	window := strings.TrimSpace(r.URL.Query().Get("window"))
	hours := 24
	switch window {
	case "", "24h":
		window, hours = "24h", 24
	case "168h", "7d":
		window, hours = "168h", 168
	case "720h", "30d":
		window, hours = "720h", 720
	default:
		writeError(w, http.StatusBadRequest, "bad_window", "仅支持 24h / 168h / 720h 窗口")
		return
	}

	var ledger AssetLedgerSnapshot
	var importedAt time.Time
	err := db.QueryRowContext(ctx, `
SELECT ledger_id, sensor_id, name, source_kind, entry_count, imported_by, imported_at, note
FROM asset_ledger_snapshots WHERE ledger_id = $1`, ledgerID).Scan(
		&ledger.LedgerID, &ledger.SensorID, &ledger.Name, &ledger.SourceKind,
		&ledger.EntryCount, &ledger.ImportedBy, &importedAt, &ledger.Note)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "ledger_not_found", "未找到指定校方台账")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ledger_load_failed", err.Error())
		return
	}
	ledger.ImportedAt = importedAt.UTC().Format(time.RFC3339)

	entryRows, err := db.QueryContext(ctx, `
SELECT mac, ip, asset_name, expected_type, expected_vendor, expected_model, department, location, asset_tag
FROM asset_ledger_entries WHERE ledger_id = $1 ORDER BY id`, ledgerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ledger_entries_read_failed", err.Error())
		return
	}
	defer entryRows.Close()
	entries := []AssetLedgerEntry{}
	for entryRows.Next() {
		var e AssetLedgerEntry
		if scanErr := entryRows.Scan(&e.MAC, &e.IP, &e.AssetName, &e.ExpectedType, &e.ExpectedVendor, &e.ExpectedModel, &e.Department, &e.Location, &e.AssetTag); scanErr == nil {
			entries = append(entries, e)
		}
	}

	// 读取当前窗口内活跃的物理 MAC 发现身份 + 跨三层已识别受管网元（含 472 CAPWAP AP / 68 SNMP 交换机）
	obsRows, err := db.QueryContext(ctx, `
WITH mac_obs AS (
  SELECT DISTINCT ON (lower(raw_mac))
    'mac:' || lower(raw_mac) AS key,
    lower(raw_mac) AS mac,
    coalesce(raw_ip, '') AS ip,
    coalesce(nullif(product_type, ''), nullif(dhcp_type, ''), '') AS observed_type,
    '' AS vendor,
    observed_at,
    'device' AS identity_kind
  FROM discovery_list_observation
  WHERE observed_at >= now() - make_interval(hours => $1)
    AND coalesce(raw_mac, '') <> ''
    AND raw_mac <> '00:00:00:00:00:00'
  ORDER BY lower(raw_mac), observed_at DESC
),
l3_obs AS (
  SELECT DISTINCT ON (raw_ip)
    'ip:' || raw_ip AS key,
    '' AS mac,
    raw_ip AS ip,
    coalesce(product_type, '') AS observed_type,
    '' AS vendor,
    observed_at,
    'l3_managed_entity' AS identity_kind
  FROM discovery_list_observation
  WHERE observed_at >= now() - make_interval(hours => $1)
    AND coalesce(raw_mac, '') = ''
    AND coalesce(raw_ip, '') <> ''
    AND product_status = 'identified'
    AND product_type <> ''
  ORDER BY raw_ip, observed_at DESC
)
SELECT key, mac, ip, observed_type, vendor, observed_at, identity_kind FROM mac_obs
UNION ALL
SELECT key, mac, ip, observed_type, vendor, observed_at, identity_kind FROM l3_obs
LIMIT 30000`, hours)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "observed_load_failed", err.Error())
		return
	}
	defer obsRows.Close()
	observed := []AssetReconcileObserved{}
	for obsRows.Next() {
		var o AssetReconcileObserved
		var lastSeen time.Time
		if scanErr := obsRows.Scan(&o.Key, &o.MAC, &o.IP, &o.ObservedType, &o.Vendor, &lastSeen, &o.IdentityKind); scanErr == nil {
			o.LastSeen = lastSeen.UTC().Format(time.RFC3339)
			observed = append(observed, o)
		}
	}

	resp := reconcileAssetLedger(ledger, window, entries, observed, time.Now().UTC())
	writeJSON(w, http.StatusOK, resp)
}

// reconcileAssetLedger 执行纯内存四象限台账对账，支持按 MAC 或 IP 精确匹配。
func reconcileAssetLedger(ledger AssetLedgerSnapshot, window string, entries []AssetLedgerEntry, observed []AssetReconcileObserved, now time.Time) AssetLedgerReconcileResponse {
	byMAC := make(map[string]AssetReconcileObserved, len(observed))
	byIP := make(map[string]AssetReconcileObserved, len(observed))
	for _, o := range observed {
		if o.MAC != "" {
			byMAC[strings.ToLower(o.MAC)] = o
		}
		if o.IP != "" {
			if _, exists := byIP[o.IP]; !exists || o.IdentityKind == "l3_managed_entity" {
				byIP[o.IP] = o
			}
		}
	}

	matchedKeys := make(map[string]bool, len(entries))
	summary := AssetLedgerReconcileSummary{
		LedgerTotal:   len(entries),
		ObservedTotal: len(observed),
	}
	items := []AssetReconcileItem{}
	countsByStatus := map[string]int{}
	truncated := false

	appendItem := func(item AssetReconcileItem) {
		if countsByStatus[item.Status] >= maxAssetReconcileItemsPerGroup {
			truncated = true
			return
		}
		countsByStatus[item.Status]++
		items = append(items, item)
	}

	// 判断台账是否聚焦于特定品类（如 AC 瘦 AP 台账只比对未登记的 access_point，避免把学生手机混进 AP 未登记清单）
	scopedType := ""
	switch strings.ToLower(strings.TrimSpace(ledger.SourceKind)) {
	case "ac_ap":
		scopedType = "access_point"
	case "switch":
		scopedType = "switch"
	case "camera":
		scopedType = "camera"
	case "printer":
		scopedType = "printer"
	}

	for _, e := range entries {
		var match AssetReconcileObserved
		found := false
		if e.MAC != "" {
			if m, ok := byMAC[strings.ToLower(e.MAC)]; ok {
				match, found = m, true
			}
		}
		if !found && e.IP != "" {
			if m, ok := byIP[e.IP]; ok {
				match, found = m, true
			}
		}
		if !found {
			summary.LedgerOffline++
			appendItem(AssetReconcileItem{
				Status:         "ledger_offline",
				MAC:            e.MAC,
				IP:             e.IP,
				AssetName:      e.AssetName,
				AssetTag:       e.AssetTag,
				Department:     e.Department,
				Location:       e.Location,
				ExpectedType:   e.ExpectedType,
				ExpectedVendor: e.ExpectedVendor,
				Detail:         "台账已登记但当前窗口未观测到活跃流量",
			})
			continue
		}
		matchedKeys[match.Key] = true
		mismatchDetail := ""
		if e.ExpectedType != "" && match.ObservedType != "" && !strings.EqualFold(e.ExpectedType, match.ObservedType) {
			mismatchDetail = fmt.Sprintf("台账品类 %s 与被动观测 %s 不符", e.ExpectedType, match.ObservedType)
		}
		if mismatchDetail != "" {
			summary.AttributeMismatch++
			appendItem(AssetReconcileItem{
				Status:         "attribute_mismatch",
				MAC:            firstNonEmptyStr(e.MAC, match.MAC),
				IP:             firstNonEmptyStr(match.IP, e.IP),
				AssetName:      e.AssetName,
				AssetTag:       e.AssetTag,
				Department:     e.Department,
				Location:       e.Location,
				ExpectedType:   e.ExpectedType,
				ObservedType:   match.ObservedType,
				ExpectedVendor: e.ExpectedVendor,
				ObservedVendor: match.Vendor,
				LastSeen:       match.LastSeen,
				Detail:         mismatchDetail,
			})
			continue
		}
		summary.RegisteredActive++
		appendItem(AssetReconcileItem{
			Status:         "registered_active",
			MAC:            firstNonEmptyStr(e.MAC, match.MAC),
			IP:             firstNonEmptyStr(match.IP, e.IP),
			AssetName:      e.AssetName,
			AssetTag:       e.AssetTag,
			Department:     e.Department,
			Location:       e.Location,
			ExpectedType:   e.ExpectedType,
			ObservedType:   match.ObservedType,
			ExpectedVendor: e.ExpectedVendor,
			ObservedVendor: match.Vendor,
			LastSeen:       match.LastSeen,
			Detail:         "已登记且在窗口内活跃",
		})
	}

	// 按最近观测排序，优先暴露新发现未登记的受管/明确类型设备
	sort.Slice(observed, func(i, j int) bool {
		return observed[i].LastSeen > observed[j].LastSeen
	})
	for _, o := range observed {
		if matchedKeys[o.Key] {
			continue
		}
		if scopedType != "" && !strings.EqualFold(o.ObservedType, scopedType) {
			continue
		}
		summary.DiscoveredUnregistered++
		appendItem(AssetReconcileItem{
			Status:         "discovered_unregistered",
			MAC:            o.MAC,
			IP:             o.IP,
			ObservedType:   o.ObservedType,
			ObservedVendor: o.Vendor,
			LastSeen:       o.LastSeen,
			Detail:         "被动发现已观测到活跃记录，但不在当前台账中",
		})
	}

	return AssetLedgerReconcileResponse{
		Ledger:       ledger,
		Window:       window,
		ReconciledAt: now.UTC().Format(time.RFC3339),
		Summary:      summary,
		Items:        items,
		Truncated:    truncated,
	}
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
