package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
)

const whitelistSettingKey = "policy_whitelist_v1"
const blacklistSettingKey = "policy_blacklist_v1"

type whitelistValidationError struct{ message string }

func (e whitelistValidationError) Error() string { return e.message }

var errWhitelistConflict = errors.New("名单已被更新，请刷新后重试")
var errWhitelistDuplicate = errors.New("相同类型、匹配值和范围的记录已存在，请编辑原记录")

type whitelistDocument struct {
	Entries []policy.WhitelistEntry `json:"entries"`
	History []json.RawMessage       `json:"history,omitempty"`
}

// whitelistManager stores one policy list document. It is shared by the
// whitelist and the blacklist so that revision handling, audit and validation
// cannot drift between the two lists; the zero value behaves as the whitelist.
type whitelistManager struct {
	db        *sql.DB
	path      string
	key       string
	idPrefix  string
	auditName string
	lockName  string
	label     string
	normalize func(*policy.WhitelistEntry) error
	mu        sync.Mutex
	doc       whitelistDocument
}

func (m *whitelistManager) settings() (key, idPrefix, auditName, lockName, label string) {
	key, idPrefix, auditName, lockName, label = m.key, m.idPrefix, m.auditName, m.lockName, m.label
	if key == "" {
		key = whitelistSettingKey
	}
	if idPrefix == "" {
		idPrefix = "whitelist-"
	}
	if auditName == "" {
		auditName = "policy.whitelist."
	}
	if lockName == "" {
		lockName = "policy-whitelist-write"
	}
	if label == "" {
		label = "白名单"
	}
	return
}

func (m *whitelistManager) normalizeEntry(entry *policy.WhitelistEntry) error {
	if m.normalize != nil {
		return m.normalize(entry)
	}
	return policy.NormalizeWhitelist(entry)
}

func newWhitelistManager(db *sql.DB, path string) *whitelistManager {
	return &whitelistManager{db: db, path: path, doc: whitelistDocument{Entries: []policy.WhitelistEntry{}}}
}

// newBlacklistManager reuses the whitelist storage contract with its own
// settings document, identifiers, audit namespace and advisory lock.
func newBlacklistManager(db *sql.DB) *whitelistManager {
	return &whitelistManager{db: db, key: blacklistSettingKey, idPrefix: "blacklist-", auditName: "policy.blacklist.", lockName: "policy-blacklist-write", label: "黑名单", normalize: policy.NormalizeBlacklist, doc: whitelistDocument{Entries: []policy.WhitelistEntry{}}}
}

func (m *whitelistManager) decode(raw []byte) (whitelistDocument, error) {
	_, _, _, _, label := m.settings()
	d := whitelistDocument{Entries: []policy.WhitelistEntry{}}
	if len(raw) > 8<<20 {
		return d, fmt.Errorf("%s配置超出大小限制", label)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &d); err != nil {
			return d, err
		}
	}
	if len(d.Entries) > 10000 {
		return d, fmt.Errorf("%s记录超出数量限制", label)
	}
	seen := map[string]bool{}
	for i := range d.Entries {
		e := &d.Entries[i]
		if e.ID == "" || seen[e.ID] || e.Revision < 1 {
			return d, fmt.Errorf("白名单配置损坏")
		}
		seen[e.ID] = true
		if err := m.normalizeEntry(e); err != nil {
			return d, err
		}
	}
	return d, nil
}
func (m *whitelistManager) read(ctx context.Context, q operationsQuerier) (whitelistDocument, error) {
	key, _, _, _, _ := m.settings()
	if m.db != nil {
		var raw []byte
		err := q.QueryRowContext(ctx, `SELECT setting_value FROM control_plane_settings WHERE setting_key=$1`, key).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return m.decode(nil)
		}
		if err != nil {
			return whitelistDocument{}, err
		}
		return m.decode(raw)
	}
	if m.path != "" {
		f, err := os.Open(m.path)
		if errors.Is(err, os.ErrNotExist) {
			return m.decode(nil)
		}
		if err != nil {
			return whitelistDocument{}, err
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
		if err != nil {
			return whitelistDocument{}, err
		}
		return m.decode(raw)
	}
	raw, _ := json.Marshal(m.doc)
	return m.decode(raw)
}
func (m *whitelistManager) list(ctx context.Context) ([]policy.WhitelistEntry, error) {
	if m == nil {
		return []policy.WhitelistEntry{}, nil
	}
	if m.db == nil {
		if err := m.lock(ctx); err != nil {
			return nil, err
		}
		defer m.mu.Unlock()
	}
	d, err := m.read(ctx, m.db)
	if err != nil {
		return nil, err
	}
	sort.Slice(d.Entries, func(i, j int) bool {
		if d.Entries[i].CreatedAt.Equal(d.Entries[j].CreatedAt) {
			return d.Entries[i].ID < d.Entries[j].ID
		}
		return d.Entries[i].CreatedAt.After(d.Entries[j].CreatedAt)
	})
	return d.Entries, nil
}
func (m *whitelistManager) save(ctx context.Context, request policy.WhitelistEntry, id, op, actor string) (policy.WhitelistEntry, error) {
	key, idPrefix, auditName, lockName, label := m.settings()
	if m.db == nil {
		if err := m.lock(ctx); err != nil {
			return request, err
		}
		defer m.mu.Unlock()
	}
	var tx *sql.Tx
	var q operationsQuerier = m.db
	if m.db != nil {
		var err error
		tx, err = m.db.BeginTx(ctx, nil)
		if err != nil {
			return request, err
		}
		defer tx.Rollback()
		q = tx
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockName); err != nil {
			return request, err
		}
	}
	d, err := m.read(ctx, q)
	if err != nil {
		return request, err
	}
	now := time.Now().UTC()
	index := -1
	var old *policy.WhitelistEntry
	if id != "" {
		for i, e := range d.Entries {
			if e.ID == id {
				index = i
				copy := e
				old = &copy
				break
			}
		}
		if index < 0 {
			return request, sql.ErrNoRows
		}
		if request.Revision != old.Revision {
			return request, errWhitelistConflict
		}
	}
	item := request
	if old != nil {
		item.ID = old.ID
		item.CreatedBy = old.CreatedBy
		item.CreatedAt = old.CreatedAt
		item.Revision = old.Revision + 1
	} else {
		if len(d.Entries) >= 10000 {
			return item, whitelistValidationError{label + "最多保存 10000 条记录"}
		}
		item.ID = idPrefix + shortToken(16)
		item.CreatedBy = actor
		item.CreatedAt = now
		item.Revision = 1
	}
	if op == "enable" || op == "disable" {
		item = *old
		item.Revision++
		item.Enabled = op == "enable"
		if item.Enabled && item.ExpiresAt != nil && !item.ExpiresAt.After(now) {
			return item, whitelistValidationError{"该" + label + "已过期，请先编辑有效期"}
		}
	}
	item.UpdatedBy = actor
	item.UpdatedAt = now
	if item.ValidFrom.IsZero() {
		item.ValidFrom = now
	}
	if err = m.normalizeEntry(&item); err != nil {
		return item, whitelistValidationError{err.Error()}
	}
	for _, e := range d.Entries {
		if e.ID != item.ID && e.Type == item.Type && e.Value == item.Value && e.CampusID == item.CampusID && e.AccessDomain == item.AccessDomain {
			return item, errWhitelistDuplicate
		}
	}
	if index < 0 {
		d.Entries = append(d.Entries, item)
	} else {
		d.Entries[index] = item
	}
	change, _ := json.Marshal(map[string]any{"previous": old, "next": item})
	action := auditName + op
	if tx != nil {
		raw, _ := json.Marshal(d)
		if len(raw) > 8<<20 {
			return item, whitelistValidationError{label + "配置超出大小限制"}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO control_plane_settings(setting_key,setting_value) VALUES($1,$2::jsonb) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=now()`, key, raw); err != nil {
			return item, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,$3,$4,$5,$6)`, "audit-"+idPrefix+shortToken(16), actor, action, item.ID, string(change), now); err != nil {
			return item, err
		}
		return item, tx.Commit()
	}
	journal, _ := json.Marshal(map[string]any{"actor": actor, "action": action, "target": item.ID, "change": json.RawMessage(change), "created_at": now})
	d.History = append(d.History, journal)
	if m.path != "" {
		raw, _ := json.Marshal(d)
		if len(raw) > 8<<20 {
			return item, whitelistValidationError{label + "配置超出大小限制"}
		}
		if err = os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
			return item, err
		}
		f, err := os.CreateTemp(filepath.Dir(m.path), ".whitelist-*")
		if err != nil {
			return item, err
		}
		name := f.Name()
		defer os.Remove(name)
		if _, err = f.Write(raw); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return item, err
		}
		if closeErr != nil {
			return item, closeErr
		}
		if err = os.Rename(name, m.path); err != nil {
			return item, err
		}
	}
	m.doc = d
	return item, nil
}

func whitelistState(e policy.WhitelistEntry, now time.Time) string {
	if !e.Enabled {
		return "disabled"
	}
	if e.ExpiresAt != nil && !now.Before(*e.ExpiresAt) {
		return "expired"
	}
	if now.Before(e.ValidFrom) {
		return "scheduled"
	}
	return "active"
}

type policyListCodes struct {
	unavailable string
	bad         string
	notFound    string
	conflict    string
	label       string
}

var whitelistCodes = policyListCodes{unavailable: "whitelist_unavailable", bad: "bad_whitelist", notFound: "whitelist_not_found", conflict: "whitelist_conflict", label: "白名单"}
var blacklistCodes = policyListCodes{unavailable: "blacklist_unavailable", bad: "bad_blacklist", notFound: "blacklist_not_found", conflict: "blacklist_conflict", label: "黑名单"}

func (s *Server) handleWhitelist(w http.ResponseWriter, r *http.Request, path string) {
	s.handlePolicyList(w, r, path, "/whitelist", s.whitelist, whitelistCodes)
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request, path string) {
	s.handlePolicyList(w, r, path, "/blacklist", s.blacklist, blacklistCodes)
}

// handlePolicyList serves both lists through the same contract so revision,
// filtering and error semantics stay identical.
func (s *Server) handlePolicyList(w http.ResponseWriter, r *http.Request, path, prefix string, manager *whitelistManager, codes policyListCodes) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	rest := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	if r.Method == http.MethodGet && rest == "" {
		limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 100)
		if err != nil {
			writeError(w, 400, "bad_page", "分页参数不正确")
			return
		}
		cursor, err := cursorOffset(r.URL.Query().Get("cursor"))
		if err != nil {
			writeError(w, 400, "bad_page", "分页参数不正确")
			return
		}
		items, err := manager.list(ctx)
		if err != nil {
			writeError(w, 503, codes.unavailable, codes.label+"读取失败")
			return
		}
		now := time.Now().UTC()
		filtered := []policy.WhitelistEntry{}
		keyword := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("keyword")))
		kind, state := r.URL.Query().Get("type"), r.URL.Query().Get("state")
		for _, e := range items {
			if kind != "" && kind != e.Type || state != "" && state != whitelistState(e, now) || keyword != "" && !strings.Contains(strings.ToLower(e.Value+" "+e.Reason+" "+e.CampusID+" "+e.AccessDomain), keyword) {
				continue
			}
			filtered = append(filtered, e)
		}
		paged, page := paginate(filtered, cursor, limit)
		writeJSON(w, 200, map[string]any{"items": paged, "page": page, "checked_at": now})
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "method_not_allowed", "该接口不支持此操作")
		return
	}
	parts := strings.Split(rest, "/")
	op, id := "create", ""
	if rest != "" {
		id = parts[0]
		op = "update"
		if len(parts) == 2 && (parts[1] == "enable" || parts[1] == "disable") {
			op = parts[1]
		} else if len(parts) != 1 {
			writeError(w, 404, codes.notFound, codes.label+"接口不存在")
			return
		}
	}
	var req policy.WhitelistEntry
	raw, readErr := io.ReadAll(io.LimitReader(r.Body, 8193))
	if readErr != nil || len(raw) > 8192 || json.Unmarshal(raw, &req) != nil {
		writeError(w, 400, codes.bad, "请提交有效的"+codes.label+"配置")
		return
	}
	if op == "create" && req.Revision != 0 {
		writeError(w, 400, codes.bad, "新增记录不能带有旧版本")
		return
	}
	item, err := manager.save(ctx, req, id, op, sessionFromContext(ctx).User.ID)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeError(w, 404, codes.notFound, codes.label+"不存在")
		case errors.Is(err, errWhitelistConflict), errors.Is(err, errWhitelistDuplicate):
			writeError(w, 409, codes.conflict, err.Error())
		default:
			var validation whitelistValidationError
			if errors.As(err, &validation) {
				writeError(w, 400, codes.bad, validation.Error())
			} else {
				writeError(w, 503, codes.unavailable, codes.label+"保存失败，请稍后重试")
			}
		}
		return
	}
	status := 200
	if op == "create" {
		status = 201
	}
	writeJSON(w, status, item)
}

func (s *Server) checkActionWhitelist(ctx context.Context, a EnforcementAction) error {
	if a.ActionType == "release" || a.ActionType == "status" {
		return ctx.Err()
	}
	entries, err := s.whitelist.list(ctx)
	if err != nil {
		return actionPrecheckReadError{cause: err}
	}
	if len(entries) == 0 {
		return ctx.Err()
	}
	now := time.Now().UTC()
	if m := policy.MatchWhitelist(entries, policy.WhitelistSubject{AccountID: a.AccountID, IP: a.IP, CampusID: a.CampusID, AccessDomain: a.PolicyParameters.AccessDomain}, now); m != nil {
		return fmt.Errorf("whitelist_suppressed: %s", m.ID)
	}
	active := false
	for _, e := range entries {
		active = active || e.Active(now)
	}
	if !active {
		return ctx.Err()
	}
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		return actionPrecheckReadError{cause: fmt.Errorf("白名单会话身份读取不可用")}
	}
	ss, err := s.policySessions(ctx, reader, now)
	if err != nil {
		return actionPrecheckReadError{cause: err}
	}
	if m := policy.MatchAccountWhitelist(entries, a.AccountID, ss, now); m != nil {
		return fmt.Errorf("whitelist_suppressed: %s", m.ID)
	}
	return ctx.Err()
}

func (m *whitelistManager) lock(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.mu.TryLock() {
			return nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
