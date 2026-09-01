package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
var casePriorities = map[string]bool{"high": true, "medium": true, "low": true}
var caseStatusTransitions = map[string]map[string]bool{
	"new":           {"assigned": true, "investigating": true, "waiting_data": true},
	"assigned":      {"investigating": true, "waiting_data": true},
	"investigating": {"waiting_data": true, "resolved": true},
	"waiting_data":  {"investigating": true, "resolved": true},
	"resolved":      {"closed": true, "reopened": true},
	"closed":        {"reopened": true},
	"reopened":      {"assigned": true, "investigating": true, "waiting_data": true, "resolved": true},
}

type RiskCase struct {
	CaseID           string                 `json:"case_id"`
	SubjectType      string                 `json:"subject_type"`
	SubjectID        string                 `json:"subject_id"`
	IP               string                 `json:"ip,omitempty"`
	AccountID        string                 `json:"account_id,omitempty"`
	EndpointID       string                 `json:"endpoint_id,omitempty"`
	CampusID         string                 `json:"campus_id,omitempty"`
	Department       string                 `json:"department,omitempty"`
	PersonType       string                 `json:"person_type,omitempty"`
	BuildingID       string                 `json:"building_id,omitempty"`
	NetworkZoneID    string                 `json:"network_zone_id,omitempty"`
	SSID             string                 `json:"ssid,omitempty"`
	VLAN             string                 `json:"vlan,omitempty"`
	AP               string                 `json:"ap,omitempty"`
	NASIP            string                 `json:"nas_ip,omitempty"`
	AuthSessionID    string                 `json:"auth_session_id,omitempty"`
	IdentityConflict bool                   `json:"identity_conflict"`
	IdentityBlocker  string                 `json:"identity_blocker,omitempty"`
	DedupeKey        string                 `json:"dedupe_key,omitempty"`
	Status           string                 `json:"status"`
	Disposition      string                 `json:"disposition,omitempty"`
	Priority         string                 `json:"priority"`
	AssigneeID       string                 `json:"assignee_id,omitempty"`
	RiskScore        int                    `json:"risk_score"`
	RiskConfidence   float64                `json:"risk_confidence"`
	AssessmentLevel  string                 `json:"assessment_level"`
	RulesetVersion   string                 `json:"ruleset_version,omitempty"`
	DueAt            string                 `json:"due_at"`
	FirstSeen        string                 `json:"first_seen"`
	LastSeen         string                 `json:"last_seen"`
	CreatedAt        string                 `json:"created_at"`
	UpdatedAt        string                 `json:"updated_at"`
	EvidenceSnapshot store.ProxyReviewCase  `json:"evidence_snapshot"`
	EvidenceHistory  []CaseEvidenceSnapshot `json:"evidence_history,omitempty"`
	Comments         []CaseComment          `json:"comments,omitempty"`
	Timeline         []CaseTimeline         `json:"timeline,omitempty"`
}

type CaseEvidenceSnapshot struct {
	SnapshotID     string                `json:"snapshot_id"`
	RulesetVersion string                `json:"ruleset_version,omitempty"`
	Evidence       store.ProxyReviewCase `json:"evidence"`
	CreatedAt      string                `json:"created_at"`
}

type SLAPolicy struct {
	PolicyID          string `json:"policy_id"`
	AssessmentLevel   string `json:"assessment_level"`
	ResponseMinutes   int    `json:"response_minutes"`
	ResolutionMinutes int    `json:"resolution_minutes"`
	Enabled           bool   `json:"enabled"`
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
	SLAPolicies  map[string]SLAPolicy         `json:"sla_policies,omitempty"`
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
	return operationsDocument{Version: 1, Cases: map[string]RiskCase{}, Campuses: map[string]Campus{}, Buildings: map[string]Building{}, NetworkZones: map[string]NetworkZone{}, AccessPoints: map[string]AccessPoint{}, Connectors: map[string]ActionConnector{}, Actions: map[string]EnforcementAction{}, SLAPolicies: defaultSLAPolicies()}
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
	if s.doc.SLAPolicies == nil {
		s.doc.SLAPolicies = defaultSLAPolicies()
	}
}

func defaultSLAPolicies() map[string]SLAPolicy {
	return map[string]SLAPolicy{
		"high":       {PolicyID: "sla-high", AssessmentLevel: "high", ResponseMinutes: 60, ResolutionMinutes: 240, Enabled: true},
		"suspicious": {PolicyID: "sla-suspicious", AssessmentLevel: "suspicious", ResponseMinutes: 240, ResolutionMinutes: 1440, Enabled: true},
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
	exceptions, err := s.exceptions.list(r.Context(), true)
	if err != nil {
		return err
	}
	attributions := map[string]store.IdentityAttribution{}
	attributionFound := map[string]bool{}
	resolver, canResolveIdentity := s.reader.(store.IdentityAttributionResolver)
	if canResolveIdentity {
		for _, item := range result.Items {
			attribution, found, resolveErr := resolver.ResolveIdentityAt(r.Context(), item.IP, item.LastSeen)
			if resolveErr != nil {
				return fmt.Errorf("resolve case identity %s: %w", item.CaseID, resolveErr)
			}
			attributions[item.CaseID], attributionFound[item.CaseID] = attribution, found
		}
	}
	now := time.Now().UTC()
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	for _, item := range result.Items {
		matchedException := matchException(exceptions, item.IP, item.AccountID, item.EndpointID, "")
		if matchedException == nil {
			for _, destination := range item.DestinationDomains {
				for index := range exceptions {
					if exceptions[index].ScopeType == "domain" && strings.EqualFold(exceptions[index].ScopeValue, destination.Value) {
						matchedException = &exceptions[index]
						break
					}
				}
			}
		}
		if matchedException != nil {
			continue
		}
		dedupeKey := caseDedupeKey(item)
		caseID := item.CaseID
		existing, ok := s.operations.doc.Cases[caseID]
		for candidateID, candidate := range s.operations.doc.Cases {
			if candidate.Status != "closed" && (candidate.DedupeKey == dedupeKey || candidate.DedupeKey == "" && candidate.SubjectID == item.IP) {
				caseID, existing, ok = candidateID, candidate, true
				break
			}
		}
		if ok && existing.Status == "closed" {
			caseID, ok = item.CaseID+"-"+shortToken(6), false
		}
		level := item.RiskLevel
		if level == "confirmed" {
			level = "high"
		}
		priority := "medium"
		if level == "high" {
			priority = "high"
		}
		if !ok {
			existing = RiskCase{CaseID: caseID, DedupeKey: dedupeKey, SubjectType: "ip", SubjectID: item.IP, IP: item.IP, AccountID: item.AccountID, EndpointID: item.EndpointID, Status: "new", Priority: priority, RulesetVersion: "review-rules-v1", CreatedAt: now.Format(time.RFC3339Nano), FirstSeen: item.FirstSeen, Timeline: []CaseTimeline{}, Comments: []CaseComment{}, EvidenceHistory: []CaseEvidenceSnapshot{}}
			existing.DueAt = caseDueAt(now, level, s.operations.doc.SLAPolicies).Format(time.RFC3339Nano)
			existing.Timeline = append(existing.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: "system", Type: "case.created", After: map[string]any{"status": "new"}, CreatedAt: now.Format(time.RFC3339Nano)})
		}
		previousScore := existing.RiskScore
		existing.RiskScore = item.RiskScore
		existing.RiskConfidence = confidenceLevelValue(item.ConfidenceLevel)
		existing.AssessmentLevel = level
		existing.LastSeen = item.LastSeen
		existing.UpdatedAt = now.Format(time.RFC3339Nano)
		existing.DedupeKey = dedupeKey
		snapshot := newCaseEvidenceSnapshot(existing.CaseID, existing.RulesetVersion, item, now)
		if len(existing.EvidenceHistory) == 0 && existing.EvidenceSnapshot.CaseID != "" {
			existing.EvidenceHistory = append(existing.EvidenceHistory, newCaseEvidenceSnapshot(existing.CaseID, existing.RulesetVersion, existing.EvidenceSnapshot, parseOrNow(existing.CreatedAt)))
		}
		if !caseEvidenceSnapshotExists(existing.EvidenceHistory, snapshot.SnapshotID) {
			existing.EvidenceHistory = append(existing.EvidenceHistory, snapshot)
			if existing.EvidenceSnapshot.CaseID == "" {
				existing.EvidenceSnapshot = item
			} else {
				existing.Timeline = append(existing.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: "system", Type: "case.evidence_appended", Before: map[string]any{"risk_score": previousScore}, After: map[string]any{"risk_score": item.RiskScore, "snapshot_id": snapshot.SnapshotID}, CreatedAt: now.Format(time.RFC3339Nano)})
			}
		}
		if attribution, found := attributions[item.CaseID]; found {
			existing.AccountID = attribution.AccountID
			existing.EndpointID = attribution.EndpointID
			existing.PersonType = attribution.PersonType
			existing.Department = attribution.Department
			existing.CampusID = attribution.CampusID
			existing.BuildingID = attribution.BuildingID
			existing.NetworkZoneID = attribution.NetworkZoneID
			existing.SSID = attribution.SSID
			existing.VLAN = attribution.VLAN
			existing.AP = attribution.AP
			existing.NASIP = attribution.NASIP
			existing.AuthSessionID = attribution.SessionID
			existing.IdentityConflict = attribution.Conflict
			existing.IdentityBlocker = attribution.ConflictReason
		} else if canResolveIdentity {
			existing.IdentityBlocker = "风险发生时间没有可准确定位的认证会话"
		} else {
			existing.IdentityBlocker = "身份关联数据源不可用"
		}
		s.operations.doc.Cases[existing.CaseID] = existing
	}
	return s.operations.saveLocked()
}

func caseDedupeKey(item store.ProxyReviewCase) string {
	rules := make([]string, 0, len(item.RuleMatches))
	for _, match := range item.RuleMatches {
		if value := strings.TrimSpace(match.Signature); value != "" {
			rules = append(rules, value)
		}
	}
	sort.Strings(rules)
	if len(rules) == 0 {
		rules = []string{"risk"}
	}
	sum := sha256.Sum256([]byte("ip\x00" + item.IP + "\x00" + strings.Join(rules, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func legacyCaseDedupeKey(subjectType, subjectID string) string {
	sum := sha256.Sum256([]byte(subjectType + "\x00" + subjectID))
	return hex.EncodeToString(sum[:16])
}

func newCaseEvidenceSnapshot(caseID, rulesetVersion string, evidence store.ProxyReviewCase, createdAt time.Time) CaseEvidenceSnapshot {
	raw, _ := json.Marshal(evidence)
	sum := sha256.Sum256(append([]byte(caseID+"\x00"+rulesetVersion+"\x00"), raw...))
	return CaseEvidenceSnapshot{SnapshotID: "case-evidence-" + hex.EncodeToString(sum[:12]), RulesetVersion: rulesetVersion, Evidence: evidence, CreatedAt: createdAt.UTC().Format(time.RFC3339Nano)}
}

func caseEvidenceSnapshotExists(items []CaseEvidenceSnapshot, snapshotID string) bool {
	for _, item := range items {
		if item.SnapshotID == snapshotID {
			return true
		}
	}
	return false
}

func parseOrNow(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Now().UTC()
	}
	return parsed
}

func caseDueAt(now time.Time, level string, policies map[string]SLAPolicy) time.Time {
	minutes := 1440
	if policy, ok := policies[level]; ok && policy.Enabled && policy.ResolutionMinutes > 0 {
		minutes = policy.ResolutionMinutes
	}
	return now.Add(time.Duration(minutes) * time.Minute)
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
	if r.Method == http.MethodPost && rest == "batch" {
		s.mutateCasesBatch(w, r)
		return
	}
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
	dimensions := map[string]string{"department": r.URL.Query().Get("department"), "person_type": r.URL.Query().Get("person_type"), "ssid": r.URL.Query().Get("ssid"), "vlan": r.URL.Query().Get("vlan"), "ap": r.URL.Query().Get("ap"), "nas_ip": r.URL.Query().Get("nas_ip")}
	s.operations.mu.Lock()
	items := []RiskCase{}
	for _, item := range s.operations.doc.Cases {
		if status != "" && item.Status != status || assignee != "" && item.AssigneeID != assignee || campus != "" && item.CampusID != campus {
			continue
		}
		if dimensions["department"] != "" && item.Department != dimensions["department"] || dimensions["person_type"] != "" && item.PersonType != dimensions["person_type"] || dimensions["ssid"] != "" && item.SSID != dimensions["ssid"] || dimensions["vlan"] != "" && item.VLAN != dimensions["vlan"] || dimensions["ap"] != "" && item.AP != dimensions["ap"] || dimensions["nas_ip"] != "" && item.NASIP != dimensions["nas_ip"] {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(strings.Join([]string{item.CaseID, item.IP, item.AccountID, item.EndpointID, item.Department}, " ")), q) {
			continue
		}
		item.Comments = nil
		item.Timeline = nil
		item.EvidenceSnapshot = store.ProxyReviewCase{}
		item.EvidenceHistory = nil
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
		Priority    string `json:"priority"`
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
	before := map[string]any{"status": item.Status, "assignee_id": item.AssigneeID, "disposition": item.Disposition, "priority": item.Priority}
	eventType := ""
	switch operation {
	case "assign":
		if strings.TrimSpace(body.AssigneeID) == "" {
			writeError(w, 400, "assignee_required", "assignee_id is required")
			return
		}
		if item.Status == "resolved" || item.Status == "closed" {
			writeError(w, 409, "case_not_open", "resolved or closed cases must be reopened before assignment")
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
		if !caseStatusTransitions[item.Status][body.Status] {
			writeError(w, 409, "invalid_case_transition", "case status transition is not allowed")
			return
		}
		if body.Status == "resolved" && item.Disposition == "" {
			writeError(w, 409, "case_disposition_required", "a disposition is required before resolving a case")
			return
		}
		item.Status = body.Status
		eventType = "case.status_changed"
	case "priority":
		if !casePriorities[body.Priority] {
			writeError(w, 400, "bad_case_priority", "unsupported case priority")
			return
		}
		item.Priority = body.Priority
		eventType = "case.priority_changed"
	case "disposition":
		if !caseDispositions[body.Disposition] {
			writeError(w, 400, "bad_case_disposition", "unsupported disposition")
			return
		}
		if item.Status == "closed" {
			writeError(w, 409, "case_closed", "closed cases must be reopened before changing disposition")
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
	item.Timeline = append(item.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: actor, Type: eventType, Before: before, After: map[string]any{"status": item.Status, "assignee_id": item.AssigneeID, "disposition": item.Disposition, "priority": item.Priority}, CreatedAt: now})
	s.operations.doc.Cases[id] = item
	if err := s.operations.saveLocked(); err != nil {
		writeError(w, 500, "save_case_failed", err.Error())
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) mutateCasesBatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CaseIDs    []string `json:"case_ids"`
		Operation  string   `json:"operation"`
		AssigneeID string   `json:"assignee_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.CaseIDs) == 0 || len(body.CaseIDs) > 100 {
		writeError(w, http.StatusBadRequest, "bad_case_batch", "case_ids must contain between 1 and 100 items")
		return
	}
	if body.Operation != "assign" && body.Operation != "close" {
		writeError(w, http.StatusBadRequest, "bad_case_batch_operation", "operation must be assign or close")
		return
	}
	if body.Operation == "assign" && strings.TrimSpace(body.AssigneeID) == "" {
		writeError(w, http.StatusBadRequest, "assignee_required", "assignee_id is required")
		return
	}
	actor := sessionFromContext(r.Context()).User.ID
	now := time.Now().UTC().Format(time.RFC3339Nano)
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	for _, caseID := range body.CaseIDs {
		item, ok := s.operations.doc.Cases[caseID]
		if !ok {
			writeError(w, http.StatusNotFound, "case_not_found", "case not found: "+caseID)
			return
		}
		if body.Operation == "close" && !caseStatusTransitions[item.Status]["closed"] {
			writeError(w, http.StatusConflict, "invalid_case_transition", "only resolved cases can be closed: "+caseID)
			return
		}
		if body.Operation == "assign" && (item.Status == "resolved" || item.Status == "closed") {
			writeError(w, http.StatusConflict, "case_not_open", "resolved or closed cases must be reopened before assignment: "+caseID)
			return
		}
	}
	items := make([]RiskCase, 0, len(body.CaseIDs))
	for _, caseID := range body.CaseIDs {
		item := s.operations.doc.Cases[caseID]
		before := map[string]any{"status": item.Status, "assignee_id": item.AssigneeID}
		if body.Operation == "assign" {
			item.AssigneeID = body.AssigneeID
			if item.Status == "new" || item.Status == "reopened" {
				item.Status = "assigned"
			}
		} else {
			item.Status = "closed"
		}
		item.UpdatedAt = now
		item.Timeline = append(item.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: actor, Type: "case.batch_" + body.Operation, Before: before, After: map[string]any{"status": item.Status, "assignee_id": item.AssigneeID}, CreatedAt: now})
		s.operations.doc.Cases[caseID] = item
		items = append(items, item)
	}
	if err := s.operations.saveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "save_case_batch_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "updated": len(items)})
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
