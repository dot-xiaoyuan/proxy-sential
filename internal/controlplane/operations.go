package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/store"
)

var caseStatuses = map[string]bool{"new": true, "assigned": true, "investigating": true, "waiting_data": true, "resolved": true, "closed": true, "reopened": true}
var caseDispositions = map[string]bool{"confirmed_proxy": true, "false_positive": true, "benign": true, "needs_more_data": true}

type RiskCase struct {
	CaseID           string                `json:"case_id"`
	SubjectType      string                `json:"subject_type"`
	SubjectID        string                `json:"subject_id"`
	IP               string                `json:"ip,omitempty"`
	AccountID        string                `json:"account_id,omitempty"`
	EndpointID       string                `json:"endpoint_id,omitempty"`
	CampusID         string                `json:"campus_id,omitempty"`
	Department       string                `json:"department,omitempty"`
	Status           string                `json:"status"`
	Disposition      string                `json:"disposition,omitempty"`
	Priority         string                `json:"priority"`
	AssigneeID       string                `json:"assignee_id,omitempty"`
	RiskScore        int                   `json:"risk_score"`
	RiskConfidence   float64               `json:"risk_confidence"`
	AssessmentLevel  string                `json:"assessment_level"`
	RulesetVersion   string                `json:"ruleset_version,omitempty"`
	DueAt            string                `json:"due_at"`
	FirstSeen        string                `json:"first_seen"`
	LastSeen         string                `json:"last_seen"`
	CreatedAt        string                `json:"created_at"`
	UpdatedAt        string                `json:"updated_at"`
	EvidenceSnapshot store.ProxyReviewCase `json:"evidence_snapshot"`
	Comments         []CaseComment         `json:"comments,omitempty"`
	Timeline         []CaseTimeline        `json:"timeline,omitempty"`
}

type CaseComment struct {
	CommentID string `json:"comment_id"`
	AuthorID  string `json:"author_id"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at"`
}

type CaseTimeline struct {
	EventID   string         `json:"event_id"`
	ActorID   string         `json:"actor_id"`
	Type      string         `json:"type"`
	Before    map[string]any `json:"before,omitempty"`
	After     map[string]any `json:"after,omitempty"`
	CreatedAt string         `json:"created_at"`
}

type Campus struct {
	CampusID string `json:"campus_id"`
	Code     string `json:"code"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
}

type Building struct {
	BuildingID string `json:"building_id"`
	CampusID   string `json:"campus_id"`
	Code       string `json:"code"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
}

type NetworkZone struct {
	NetworkZoneID string   `json:"network_zone_id"`
	CampusID      string   `json:"campus_id"`
	BuildingID    string   `json:"building_id,omitempty"`
	Name          string   `json:"name"`
	CIDRs         []string `json:"cidrs"`
	SSIDs         []string `json:"ssids"`
	VLANs         []string `json:"vlans"`
	Enabled       bool     `json:"enabled"`
}

type AccessPoint struct {
	AccessPointID string `json:"access_point_id"`
	CampusID      string `json:"campus_id"`
	BuildingID    string `json:"building_id,omitempty"`
	NetworkZoneID string `json:"network_zone_id,omitempty"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	ManagementIP  string `json:"management_ip,omitempty"`
	Enabled       bool   `json:"enabled"`
}

type operationsDocument struct {
	Version      int                          `json:"version"`
	Cases        map[string]RiskCase          `json:"cases"`
	Campuses     map[string]Campus            `json:"campuses"`
	Buildings    map[string]Building          `json:"buildings"`
	NetworkZones map[string]NetworkZone       `json:"network_zones"`
	AccessPoints map[string]AccessPoint       `json:"access_points"`
	Connectors   map[string]ActionConnector   `json:"connectors,omitempty"`
	Actions      map[string]EnforcementAction `json:"actions,omitempty"`
	GlobalStop   bool                         `json:"global_stop"`
}

type operationsState struct {
	mu        operationsMutex
	path      string
	doc       operationsDocument
	db        *sql.DB
	tx        *sql.Tx
	txCancel  context.CancelFunc
	lockErr   error
	healthMu  sync.RWMutex
	healthErr error
}

type operationsMutex struct {
	sync.Mutex
	owner *operationsState
}

func (m *operationsMutex) Lock() {
	m.Mutex.Lock()
	if m.owner != nil {
		m.owner.beginLocked()
	}
}

func (m *operationsMutex) Unlock() {
	if m.owner != nil {
		m.owner.endLocked()
	}
	m.Mutex.Unlock()
}

func newOperationsState(path, postgresDSN string) (*operationsState, error) {
	state := &operationsState{path: path, doc: emptyOperationsDocument()}
	state.mu.owner = state
	if strings.TrimSpace(postgresDSN) != "" {
		db, err := sql.Open("pgx", postgresDSN)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
		db.SetConnMaxIdleTime(5 * time.Minute)
		state.db = db
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("connect PostgreSQL operations repository: %w", err)
		}
		if err := state.reloadPostgres(ctx, db); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("load PostgreSQL operations repository: %w", err)
		}
		if path != "" && operationsDocumentEmpty(state.doc) {
			data, readErr := os.ReadFile(path)
			if readErr == nil {
				var imported operationsDocument
				if err := json.Unmarshal(data, &imported); err != nil {
					_ = db.Close()
					return nil, fmt.Errorf("decode legacy operations state: %w", err)
				}
				state.mu.Lock()
				state.doc = imported
				state.ensureMaps()
				err = state.saveLocked()
				state.mu.Unlock()
				if err != nil {
					_ = db.Close()
					return nil, fmt.Errorf("import legacy operations state: %w", err)
				}
			} else if !os.IsNotExist(readErr) {
				_ = db.Close()
				return nil, readErr
			}
		}
		return state, nil
	}
	if path == "" {
		return state, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &state.doc); err != nil {
		return nil, err
	}
	state.ensureMaps()
	return state, nil
}

func operationsDocumentEmpty(doc operationsDocument) bool {
	return len(doc.Cases) == 0 && len(doc.Campuses) == 0 && len(doc.Buildings) == 0 && len(doc.NetworkZones) == 0 && len(doc.AccessPoints) == 0 && len(doc.Connectors) == 0 && len(doc.Actions) == 0 && !doc.GlobalStop
}

func emptyOperationsDocument() operationsDocument {
	return operationsDocument{Version: 1, Cases: map[string]RiskCase{}, Campuses: map[string]Campus{}, Buildings: map[string]Building{}, NetworkZones: map[string]NetworkZone{}, AccessPoints: map[string]AccessPoint{}, Connectors: map[string]ActionConnector{}, Actions: map[string]EnforcementAction{}}
}

func (s *operationsState) ensureMaps() {
	if s.doc.Cases == nil {
		s.doc.Cases = map[string]RiskCase{}
	}
	if s.doc.Campuses == nil {
		s.doc.Campuses = map[string]Campus{}
	}
	if s.doc.Buildings == nil {
		s.doc.Buildings = map[string]Building{}
	}
	if s.doc.NetworkZones == nil {
		s.doc.NetworkZones = map[string]NetworkZone{}
	}
	if s.doc.AccessPoints == nil {
		s.doc.AccessPoints = map[string]AccessPoint{}
	}
	if s.doc.Connectors == nil {
		s.doc.Connectors = map[string]ActionConnector{}
	}
	if s.doc.Actions == nil {
		s.doc.Actions = map[string]EnforcementAction{}
	}
}

func (s *operationsState) saveLocked() error {
	if s.lockErr != nil {
		return s.lockErr
	}
	if s.db != nil {
		if s.tx == nil {
			return fmt.Errorf("PostgreSQL operations transaction is not active")
		}
		if err := s.savePostgres(s.tx); err != nil {
			s.lockErr = err
			s.setHealthError(err)
			return err
		}
		return nil
	}
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	temporary := s.path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(temporary, s.path)
}

func (s *Server) syncCases(r *http.Request) error {
	window := firstNonEmptyString(r.URL.Query().Get("window"), "7d")
	result, err := s.reader.GetProxyReviews(r.Context(), store.ActivityQuery{SensorID: r.URL.Query().Get("sensor_id"), Window: window, SampleLimit: maxProxyReviewAggregateRows})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	for _, item := range result.Items {
		existing, ok := s.operations.doc.Cases[item.CaseID]
		if ok && existing.Status == "closed" {
			continue
		}
		level := item.RiskLevel
		if level == "confirmed" {
			level = "high"
		}
		priority := "medium"
		due := now.Add(24 * time.Hour)
		if level == "high" {
			priority, due = "high", now.Add(4*time.Hour)
		}
		if !ok {
			existing = RiskCase{CaseID: item.CaseID, SubjectType: "ip", SubjectID: item.IP, IP: item.IP, AccountID: item.AccountID, EndpointID: item.EndpointID, Status: "new", Priority: priority, CreatedAt: now.Format(time.RFC3339Nano), FirstSeen: item.FirstSeen, Timeline: []CaseTimeline{}, Comments: []CaseComment{}}
			existing.Timeline = append(existing.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: "system", Type: "case.created", After: map[string]any{"status": "new"}, CreatedAt: now.Format(time.RFC3339Nano)})
		}
		existing.RiskScore = item.RiskScore
		existing.RiskConfidence = confidenceLevelValue(item.ConfidenceLevel)
		existing.AssessmentLevel = level
		existing.LastSeen = item.LastSeen
		existing.UpdatedAt = now.Format(time.RFC3339Nano)
		existing.DueAt = due.Format(time.RFC3339Nano)
		existing.EvidenceSnapshot = item
		s.operations.doc.Cases[item.CaseID] = existing
	}
	return s.operations.saveLocked()
}

func confidenceLevelValue(level string) float64 {
	switch strings.ToLower(level) {
	case "high":
		return .92
	case "medium":
		return .65
	default:
		return .35
	}
}

func (s *Server) handleCases(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/cases"), "/") == "" {
		if err := s.syncCases(r); err != nil {
			writeError(w, 500, "sync_cases_failed", err.Error())
			return
		}
		s.listCases(w, r)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/cases"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, 404, "not_found", "case not found")
		return
	}
	caseID, err := store.DecodePathIP(parts[0])
	if err != nil {
		writeError(w, 400, "bad_case_id", err.Error())
		return
	}
	if r.Method == http.MethodGet && len(parts) == 1 {
		s.getCase(w, caseID)
		return
	}
	if r.Method != http.MethodPost || len(parts) != 2 {
		writeError(w, 404, "not_found", "case operation not found")
		return
	}
	s.mutateCase(w, r, caseID, parts[1])
}

func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
	limit, _ := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	cursor, _ := cursorOffset(r.URL.Query().Get("cursor"))
	q, status, assignee, campus := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))), r.URL.Query().Get("status"), r.URL.Query().Get("assignee_id"), r.URL.Query().Get("campus_id")
	s.operations.mu.Lock()
	items := []RiskCase{}
	for _, item := range s.operations.doc.Cases {
		if status != "" && item.Status != status || assignee != "" && item.AssigneeID != assignee || campus != "" && item.CampusID != campus {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(strings.Join([]string{item.CaseID, item.IP, item.AccountID, item.EndpointID, item.Department}, " ")), q) {
			continue
		}
		item.Comments = nil
		item.Timeline = nil
		item.EvidenceSnapshot = store.ProxyReviewCase{}
		items = append(items, item)
	}
	s.operations.mu.Unlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].Priority != items[j].Priority {
			return items[i].Priority < items[j].Priority
		}
		return items[i].UpdatedAt > items[j].UpdatedAt
	})
	paged, page := paginate(items, cursor, limit)
	writeJSON(w, 200, map[string]any{"items": paged, "page": page})
}

func (s *Server) getCase(w http.ResponseWriter, id string) {
	s.operations.mu.Lock()
	item, ok := s.operations.doc.Cases[id]
	s.operations.mu.Unlock()
	if !ok {
		writeError(w, 404, "case_not_found", "case not found")
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) mutateCase(w http.ResponseWriter, r *http.Request, id, operation string) {
	var body struct {
		AssigneeID  string `json:"assignee_id"`
		Status      string `json:"status"`
		Disposition string `json:"disposition"`
		Comment     string `json:"comment"`
		Reason      string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "bad_case_request", err.Error())
		return
	}
	actor := sessionFromContext(r.Context()).User.ID
	now := time.Now().UTC().Format(time.RFC3339Nano)
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	item, ok := s.operations.doc.Cases[id]
	if !ok {
		writeError(w, 404, "case_not_found", "case not found")
		return
	}
	before := map[string]any{"status": item.Status, "assignee_id": item.AssigneeID, "disposition": item.Disposition}
	eventType := ""
	switch operation {
	case "assign":
		if strings.TrimSpace(body.AssigneeID) == "" {
			writeError(w, 400, "assignee_required", "assignee_id is required")
			return
		}
		item.AssigneeID = body.AssigneeID
		if item.Status == "new" {
			item.Status = "assigned"
		}
		eventType = "case.assigned"
	case "status":
		if !caseStatuses[body.Status] {
			writeError(w, 400, "bad_case_status", "unsupported case status")
			return
		}
		item.Status = body.Status
		eventType = "case.status_changed"
	case "disposition":
		if !caseDispositions[body.Disposition] {
			writeError(w, 400, "bad_case_disposition", "unsupported disposition")
			return
		}
		item.Disposition = body.Disposition
		item.Status = "resolved"
		eventType = "case.resolved"
	case "comments":
		body.Comment = strings.TrimSpace(body.Comment)
		if len(body.Comment) < 2 {
			writeError(w, 400, "bad_comment", "comment must contain at least two characters")
			return
		}
		comment := CaseComment{CommentID: "comment-" + shortToken(8), AuthorID: actor, Body: body.Comment, CreatedAt: now}
		item.Comments = append(item.Comments, comment)
		eventType = "case.commented"
	default:
		writeError(w, 404, "case_operation_not_found", "case operation not found")
		return
	}
	item.UpdatedAt = now
	item.Timeline = append(item.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: actor, Type: eventType, Before: before, After: map[string]any{"status": item.Status, "assignee_id": item.AssigneeID, "disposition": item.Disposition}, CreatedAt: now})
	s.operations.doc.Cases[id] = item
	if err := s.operations.saveLocked(); err != nil {
		writeError(w, 500, "save_case_failed", err.Error())
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) handleOrganization(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/organization"), "/")
	s.operations.mu.Lock()
	if r.Method == http.MethodGet {
		result := map[string]any{"campuses": mapValues(s.operations.doc.Campuses), "buildings": mapValues(s.operations.doc.Buildings), "network_zones": mapValues(s.operations.doc.NetworkZones), "access_points": mapValues(s.operations.doc.AccessPoints)}
		s.operations.mu.Unlock()
		writeJSON(w, 200, result)
		return
	}
	if r.Method != http.MethodPost {
		s.operations.mu.Unlock()
		writeError(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	var result any
	target := rest
	switch rest {
	case "campuses":
		var item Campus
		if json.NewDecoder(r.Body).Decode(&item) != nil || item.CampusID == "" || item.Name == "" {
			s.operations.mu.Unlock()
			writeError(w, 400, "bad_campus", "campus_id and name are required")
			return
		}
		item.Enabled = true
		s.operations.doc.Campuses[item.CampusID] = item
		result, target = item, item.CampusID
	case "buildings":
		var item Building
		if json.NewDecoder(r.Body).Decode(&item) != nil || item.BuildingID == "" || s.operations.doc.Campuses[item.CampusID].CampusID == "" {
			s.operations.mu.Unlock()
			writeError(w, 400, "bad_building", "valid campus_id and building_id are required")
			return
		}
		item.Enabled = true
		s.operations.doc.Buildings[item.BuildingID] = item
		result, target = item, item.BuildingID
	case "network-zones":
		var item NetworkZone
		if json.NewDecoder(r.Body).Decode(&item) != nil || item.NetworkZoneID == "" || s.operations.doc.Campuses[item.CampusID].CampusID == "" {
			s.operations.mu.Unlock()
			writeError(w, 400, "bad_network_zone", "valid campus_id and network_zone_id are required")
			return
		}
		item.Enabled = true
		s.operations.doc.NetworkZones[item.NetworkZoneID] = item
		result, target = item, item.NetworkZoneID
	case "access-points":
		var item AccessPoint
		if json.NewDecoder(r.Body).Decode(&item) != nil || item.AccessPointID == "" || s.operations.doc.Campuses[item.CampusID].CampusID == "" {
			s.operations.mu.Unlock()
			writeError(w, 400, "bad_access_point", "valid campus_id and access_point_id are required")
			return
		}
		item.Enabled = true
		s.operations.doc.AccessPoints[item.AccessPointID] = item
		result, target = item, item.AccessPointID
	default:
		s.operations.mu.Unlock()
		writeError(w, 404, "organization_endpoint_not_found", "organization endpoint not found")
		return
	}
	if err := s.operations.saveLocked(); err != nil {
		s.operations.mu.Unlock()
		writeError(w, 500, "save_organization_failed", err.Error())
		return
	}
	s.operations.mu.Unlock()
	s.appendAudit(r.Context(), "organization.update", target, "succeeded")
	writeJSON(w, 201, result)
}

func mapValues[K comparable, V any](source map[K]V) []V {
	values := make([]V, 0, len(source))
	for _, value := range source {
		values = append(values, value)
	}
	return values
}

func (s *Server) applyCaseDispositionByTarget(targetID, disposition, actor string) {
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for id, item := range s.operations.doc.Cases {
		if item.SubjectID != targetID && item.IP != targetID {
			continue
		}
		item.Disposition = disposition
		item.Status = "resolved"
		item.UpdatedAt = now
		item.Timeline = append(item.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: actor, Type: "case.resolved_from_label", After: map[string]any{"disposition": disposition}, CreatedAt: now})
		s.operations.doc.Cases[id] = item
	}
	_ = s.operations.saveLocked()
}

func (s *Server) operationsSummary() map[string]int {
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	result := map[string]int{"open": 0, "overdue": 0, "resolved": 0}
	now := time.Now().UTC()
	for _, item := range s.operations.doc.Cases {
		if item.Status == "resolved" || item.Status == "closed" {
			result["resolved"]++
			continue
		}
		result["open"]++
		if due, err := time.Parse(time.RFC3339Nano, item.DueAt); err == nil && due.Before(now) {
			result["overdue"]++
		}
	}
	return result
}

func validateOperationsPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("operations path is required")
	}
	return nil
}
