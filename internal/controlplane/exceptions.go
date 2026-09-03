package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
)

type CampusException struct {
	ExceptionID    string `json:"exception_id"`
	ScopeType      string `json:"scope_type"`
	ScopeValue     string `json:"scope_value"`
	CampusID       string `json:"campus_id,omitempty"`
	Reason         string `json:"reason"`
	RulesetVersion string `json:"ruleset_version"`
	ValidFrom      string `json:"valid_from"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	Enabled        bool   `json:"enabled"`
	CreatedBy      string `json:"created_by"`
	CreatedAt      string `json:"created_at"`
}

type exceptionManager struct {
	mu    sync.RWMutex
	db    *sql.DB
	items map[string]CampusException
}

func newExceptionManager(db *sql.DB) *exceptionManager {
	return &exceptionManager{db: db, items: map[string]CampusException{}}
}

func (s *Server) handleCampusExceptions(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/campus-exceptions"), "/")
	if r.Method == http.MethodGet && rest == "" {
		items, err := s.exceptions.list(r.Context(), false)
		if err != nil {
			writeError(w, 500, "list_exceptions_failed", err.Error())
			return
		}
		limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_page", err.Error())
			return
		}
		cursor, err := cursorOffset(r.URL.Query().Get("cursor"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_page", err.Error())
			return
		}
		paged, page := paginate(items, cursor, limit)
		writeJSON(w, 200, map[string]any{"items": paged, "page": page})
		return
	}
	if r.Method == http.MethodPost && rest == "" {
		var item CampusException
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			writeError(w, 400, "bad_exception", err.Error())
			return
		}
		item.ExceptionID = "exception-" + shortToken(8)
		item.ScopeType = strings.ToLower(strings.TrimSpace(item.ScopeType))
		item.ScopeValue = strings.TrimSpace(item.ScopeValue)
		item.Reason = strings.TrimSpace(item.Reason)
		item.RulesetVersion = firstNonEmptyString(strings.TrimSpace(item.RulesetVersion), "campus-exceptions-v1")
		item.ValidFrom = firstNonEmptyString(item.ValidFrom, time.Now().UTC().Format(time.RFC3339Nano))
		item.Enabled = true
		item.CreatedBy = sessionFromContext(r.Context()).User.ID
		item.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if !map[string]bool{"ip": true, "account": true, "endpoint": true, "campus": true, "domain": true, "cidr": true}[item.ScopeType] || item.ScopeValue == "" || len(item.Reason) < 2 {
			writeError(w, 400, "bad_exception", "valid scope_type, scope_value and reason are required")
			return
		}
		if err := s.exceptions.save(r.Context(), item); err != nil {
			writeError(w, 500, "save_exception_failed", err.Error())
			return
		}
		s.appendAudit(r.Context(), "risk.exception_created", item.ExceptionID, "succeeded")
		writeJSON(w, 201, item)
		return
	}
	if r.Method == http.MethodPost && strings.HasSuffix(rest, "/disable") {
		id := strings.TrimSuffix(rest, "/disable")
		item, err := s.exceptions.disable(r.Context(), id)
		if err == sql.ErrNoRows {
			writeError(w, 404, "exception_not_found", "exception not found")
			return
		}
		if err != nil {
			writeError(w, 500, "disable_exception_failed", err.Error())
			return
		}
		s.appendAudit(r.Context(), "risk.exception_disabled", id, "succeeded")
		writeJSON(w, 200, item)
		return
	}
	writeError(w, 404, "exception_endpoint_not_found", "exception endpoint not found")
}

func (m *exceptionManager) list(ctx context.Context, activeOnly bool) ([]CampusException, error) {
	if m.db == nil {
		m.mu.RLock()
		defer m.mu.RUnlock()
		items := make([]CampusException, 0, len(m.items))
		for _, item := range m.items {
			if !activeOnly || exceptionActive(item, time.Now().UTC()) {
				items = append(items, item)
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt > items[j].CreatedAt })
		return items, nil
	}
	where := ""
	if activeOnly {
		where = ` WHERE enabled=true AND valid_from<=now() AND (expires_at IS NULL OR expires_at>now())`
	}
	rows, err := m.db.QueryContext(ctx, `SELECT exception_id,scope_type,scope_value,COALESCE(campus_id,''),reason,ruleset_version,valid_from,expires_at,enabled,created_by,created_at FROM campus_exceptions`+where+` ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []CampusException{}
	for rows.Next() {
		var item CampusException
		var validFrom, createdAt time.Time
		var expires sql.NullTime
		if err := rows.Scan(&item.ExceptionID, &item.ScopeType, &item.ScopeValue, &item.CampusID, &item.Reason, &item.RulesetVersion, &validFrom, &expires, &item.Enabled, &item.CreatedBy, &createdAt); err != nil {
			return nil, err
		}
		item.ValidFrom = formatDBTime(validFrom)
		item.CreatedAt = formatDBTime(createdAt)
		if expires.Valid {
			item.ExpiresAt = formatDBTime(expires.Time)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (m *exceptionManager) save(ctx context.Context, item CampusException) error {
	if m.db == nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.items[item.ExceptionID] = item
		return nil
	}
	_, err := m.db.ExecContext(ctx, `INSERT INTO campus_exceptions(exception_id,scope_type,scope_value,campus_id,reason,ruleset_version,valid_from,expires_at,enabled,created_by,created_at) VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7::timestamptz,NULLIF($8,'')::timestamptz,$9,$10,$11::timestamptz)`, item.ExceptionID, item.ScopeType, item.ScopeValue, item.CampusID, item.Reason, item.RulesetVersion, item.ValidFrom, item.ExpiresAt, item.Enabled, item.CreatedBy, item.CreatedAt)
	return err
}
func (m *exceptionManager) disable(ctx context.Context, id string) (CampusException, error) {
	if m.db == nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		item, ok := m.items[id]
		if !ok {
			return CampusException{}, sql.ErrNoRows
		}
		item.Enabled = false
		m.items[id] = item
		return item, nil
	}
	result, err := m.db.ExecContext(ctx, `UPDATE campus_exceptions SET enabled=false WHERE exception_id=$1`, id)
	if err != nil {
		return CampusException{}, err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return CampusException{}, sql.ErrNoRows
	}
	items, err := m.list(ctx, false)
	if err != nil {
		return CampusException{}, err
	}
	for _, item := range items {
		if item.ExceptionID == id {
			return item, nil
		}
	}
	return CampusException{}, sql.ErrNoRows
}

func exceptionActive(item CampusException, now time.Time) bool {
	if !item.Enabled {
		return false
	}
	from, err := time.Parse(time.RFC3339Nano, item.ValidFrom)
	if err == nil && from.After(now) {
		return false
	}
	if item.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339Nano, item.ExpiresAt)
		if err == nil && !expires.After(now) {
			return false
		}
	}
	return true
}

func (m *exceptionManager) apply(ctx context.Context, item *risk.Snapshot, campusID string) (*CampusException, error) {
	items, err := m.list(ctx, true)
	if err != nil {
		return nil, err
	}
	exception := matchException(items, item.IP, item.AccountID, item.EndpointID, campusID)
	if exception != nil {
		item.AssessmentLevel = "benign"
		item.AutomationEligible = false
		item.AutomationBlockers = appendUnique(item.AutomationBlockers, "campus_exception_applied")
	}
	return exception, nil
}

func matchException(items []CampusException, ip, accountID, endpointID, campusID string) *CampusException {
	for index := range items {
		exception := &items[index]
		if exception.CampusID != "" && exception.CampusID != campusID {
			continue
		}
		matched := false
		switch exception.ScopeType {
		case "ip":
			matched = ip == exception.ScopeValue
		case "account":
			matched = accountID == exception.ScopeValue
		case "endpoint":
			matched = endpointID == exception.ScopeValue
		case "campus":
			matched = campusID == exception.ScopeValue
		case "cidr":
			parsedIP := net.ParseIP(ip)
			_, network, err := net.ParseCIDR(exception.ScopeValue)
			matched = err == nil && parsedIP != nil && network.Contains(parsedIP)
		}
		if matched {
			return exception
		}
	}
	return nil
}

func matchEvidenceException(items []CampusException, evidenceItems []evidence.Evidence, campusID string) *CampusException {
	for index := range items {
		exception := &items[index]
		if exception.ScopeType != "domain" || (exception.CampusID != "" && exception.CampusID != campusID) {
			continue
		}
		needle := strings.ToLower(exception.ScopeValue)
		for _, item := range evidenceItems {
			if strings.Contains(strings.ToLower(item.Reason), needle) {
				return exception
			}
			for _, sample := range item.Samples {
				if strings.Contains(strings.ToLower(sample), needle) {
					return exception
				}
			}
		}
	}
	return nil
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
