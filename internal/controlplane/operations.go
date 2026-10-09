package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
)

var caseStatuses = map[string]bool{"new": true, "assigned": true, "investigating": true, "waiting_data": true, "resolved": true, "closed": true, "reopened": true}
var caseDispositions = map[string]bool{"confirmed_proxy": true, "confirmed_shared_access": true, "confirmed_router": true, "false_positive": true, "benign": true, "needs_more_data": true}
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
	CaseID              string                 `json:"case_id"`
	SubjectType         string                 `json:"subject_type"`
	SubjectID           string                 `json:"subject_id"`
	IP                  string                 `json:"ip,omitempty"`
	AccountID           string                 `json:"account_id,omitempty"`
	EndpointID          string                 `json:"endpoint_id,omitempty"`
	CampusID            string                 `json:"campus_id,omitempty"`
	Department          string                 `json:"department,omitempty"`
	PersonType          string                 `json:"person_type,omitempty"`
	BuildingID          string                 `json:"building_id,omitempty"`
	NetworkZoneID       string                 `json:"network_zone_id,omitempty"`
	SSID                string                 `json:"ssid,omitempty"`
	VLAN                string                 `json:"vlan,omitempty"`
	AP                  string                 `json:"ap,omitempty"`
	NASIP               string                 `json:"nas_ip,omitempty"`
	AuthSessionID       string                 `json:"auth_session_id,omitempty"`
	IdentityConflict    bool                   `json:"identity_conflict"`
	IdentityBlocker     string                 `json:"identity_blocker,omitempty"`
	DedupeKey           string                 `json:"dedupe_key,omitempty"`
	Status              string                 `json:"status"`
	Disposition         string                 `json:"disposition,omitempty"`
	Priority            string                 `json:"priority"`
	AssigneeID          string                 `json:"assignee_id,omitempty"`
	RiskScore           int                    `json:"risk_score"`
	RiskConfidence      float64                `json:"risk_confidence"`
	AssessmentLevel     string                 `json:"assessment_level"`
	AssessmentCurrent   bool                   `json:"assessment_current"`
	AssessmentUpdatedAt string                 `json:"assessment_updated_at,omitempty"`
	AssessmentWindow    string                 `json:"assessment_window,omitempty"`
	RiskKind            string                 `json:"risk_kind,omitempty"`
	RulesetVersion      string                 `json:"ruleset_version,omitempty"`
	DueAt               string                 `json:"due_at"`
	FirstSeen           string                 `json:"first_seen"`
	LastSeen            string                 `json:"last_seen"`
	CreatedAt           string                 `json:"created_at"`
	UpdatedAt           string                 `json:"updated_at"`
	EvidenceSnapshot    store.ProxyReviewCase  `json:"evidence_snapshot"`
	EvidenceHistory     []CaseEvidenceSnapshot `json:"evidence_history,omitempty"`
	HistoryPage         map[string]store.Page  `json:"history_page,omitempty"`
	Comments            []CaseComment          `json:"comments,omitempty"`
	Timeline            []CaseTimeline         `json:"timeline,omitempty"`
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
	policyVersions   map[[2]string]time.Time
	Policies         map[string]policy.Definition `json:"policies"`
	PolicyExecutions map[string]policy.Execution  `json:"policy_executions"`
	Version          int                          `json:"version"`
	Cases            map[string]RiskCase          `json:"cases"`
	Campuses         map[string]Campus            `json:"campuses"`
	Buildings        map[string]Building          `json:"buildings"`
	NetworkZones     map[string]NetworkZone       `json:"network_zones"`
	AccessPoints     map[string]AccessPoint       `json:"access_points"`
	Connectors       map[string]ActionConnector   `json:"connectors,omitempty"`
	Actions          map[string]EnforcementAction `json:"actions,omitempty"`
	SLAPolicies      map[string]SLAPolicy         `json:"sla_policies,omitempty"`
	GlobalStop       bool                         `json:"global_stop"`
}

type operationsState struct {
	recordBaseline        map[[2]string][32]byte
	recordVersionBaseline map[[2]string]string
	caseVersionBaseline   map[string]string
	readView              bool
	shadowMetricsPrepared bool
	organizationBaseline  map[[2]string]string
	persistedHistory      map[[2]string]bool
	mu                    operationsMutex
	path                  string
	doc                   operationsDocument
	db                    *sql.DB
	tx                    *sql.Tx
	txCancel              context.CancelFunc
	lockErr               error
	healthMu              sync.RWMutex
	healthErr             error
	caseSyncHealthErr     error
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
	return operationsDocument{Policies: map[string]policy.Definition{}, PolicyExecutions: map[string]policy.Execution{}, Version: 1, Cases: map[string]RiskCase{}, Campuses: map[string]Campus{}, Buildings: map[string]Building{}, NetworkZones: map[string]NetworkZone{}, AccessPoints: map[string]AccessPoint{}, Connectors: map[string]ActionConnector{}, Actions: map[string]EnforcementAction{}, SLAPolicies: defaultSLAPolicies()}
}

func (s *operationsState) ensureMaps() {
	if s.doc.Policies == nil {
		s.doc.Policies = map[string]policy.Definition{}
	}
	if s.doc.PolicyExecutions == nil {
		s.doc.PolicyExecutions = map[string]policy.Execution{}
	}
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
		// A successful synchronous save must be committed before a handler can
		// write its success response. Unlock must not hide a later commit error.
		err := s.tx.Commit()
		s.tx = nil
		if s.txCancel != nil {
			s.txCancel()
			s.txCancel = nil
		}
		if err != nil {
			s.lockErr = fmt.Errorf("commit PostgreSQL operations: %w", err)
			s.setHealthError(s.lockErr)
			return s.lockErr
		}
		s.setHealthError(nil)
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
	return s.syncCasesContext(r.Context(), r.URL.Query().Get("sensor_id"), window)
}

func (s *Server) syncCasesContext(ctx context.Context, sensorID, window string) error {
	sharedReader, ok := s.reader.(store.SharedBehaviorReader)
	if !ok {
		return fmt.Errorf("shared behavior reader unavailable")
	}
	items := []store.ProxyReviewCase{}
	closableKinds := map[string]bool{}
	sharedQuery := store.SharedBehaviorQuery{Status: "confirmed", CoverageState: "verified", Limit: 100}
	for {
		page, err := sharedReader.ListSharedBehavior(ctx, sharedQuery)
		if err != nil {
			return err
		}
		for _, assessment := range page.Items {
			if assessment.Status != "confirmed" || assessment.CoverageState != "verified" || assessment.StrongAnchor == "" || assessment.DeviceLowerBound < 2 || len(assessment.Conflicts) > 0 {
				continue
			}
			items = append(items, proxyReviewCaseForSharedAssessment(assessment))
		}
		if page.Page.NextCursor == nil {
			break
		}
		next, err := strconv.Atoi(*page.Page.NextCursor)
		if err != nil {
			return err
		}
		sharedQuery.Cursor = next
	}
	// ListSharedBehavior only exposes the atomically published current set. A
	// successful empty read therefore represents a verified negative generation.
	closableKinds["shared_access"] = true
	if routerReader, available := s.reader.(store.RouterObservationReader); available {
		routerQuery := store.RouterQuery{Role: "router", IncludeCandidates: true, Limit: 100}
		for {
			page, err := routerReader.ListRouterObservations(ctx, routerQuery)
			if err != nil {
				return err
			}
			for _, assessment := range page.Items {
				if assessment.Ambiguous || assessment.BrandReferenceOnly || (assessment.Status != "candidate" && assessment.Status != "likely" && assessment.Status != "confirmed") {
					continue
				}
				items = append(items, proxyReviewCaseForRouterAssessment(assessment))
			}
			if page.Page.NextCursor == nil {
				break
			}
			next, err := strconv.Atoi(*page.Page.NextCursor)
			if err != nil {
				return err
			}
			routerQuery.Cursor = next
		}
		closableKinds["router_observation"] = true
	}
	exceptions, err := s.exceptions.list(ctx, true)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	active := map[string]bool{}
	for _, item := range items {
		kind := caseRiskKind(item)
		if kind == "" {
			continue
		}
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
		dedupeKey := strings.ReplaceAll(kind, "_", "-") + ":" + item.CaseID
		active[dedupeKey] = true
		caseID := item.CaseID
		existing, found := s.operations.doc.Cases[caseID]
		for candidateID, candidate := range s.operations.doc.Cases {
			if activeCaseMatches(candidate, item, dedupeKey) {
				caseID, existing, found = candidateID, candidate, true
				break
			}
		}
		if found && (existing.Status == "closed" || existing.Status == "resolved") {
			caseID, found = item.CaseID+"-"+shortToken(6), false
		}
		level, rulesetVersion := caseAssessmentLevel(item), caseRulesetVersion(item)
		slaLevel, priority := "medium", "medium"
		if kind == "shared_access" {
			slaLevel, priority = "high", "high"
		} else if level == "candidate" || level == "likely" {
			slaLevel, priority = "low", "low"
		}
		if !found {
			existing = RiskCase{CaseID: caseID, DedupeKey: dedupeKey, SubjectType: "ip", SubjectID: item.IP, IP: item.IP, EndpointID: item.EndpointID, Status: "new", Priority: priority, RulesetVersion: rulesetVersion, RiskKind: kind, CreatedAt: now.Format(time.RFC3339Nano), FirstSeen: item.FirstSeen, Timeline: []CaseTimeline{}, Comments: []CaseComment{}, EvidenceHistory: []CaseEvidenceSnapshot{}}
			existing.DueAt = caseDueAt(now, slaLevel, s.operations.doc.SLAPolicies).Format(time.RFC3339Nano)
			existing.Timeline = append(existing.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: "system", Type: "case.created", After: map[string]any{"status": "new", "risk_kind": kind}, CreatedAt: now.Format(time.RFC3339Nano)})
		}
		previousScore := existing.RiskScore
		existing.RiskScore = item.RiskScore
		existing.RiskConfidence = caseRiskConfidence(item)
		existing.AssessmentLevel = level
		existing.AssessmentCurrent = true
		existing.AssessmentUpdatedAt = item.LastSeen
		existing.AssessmentWindow = window
		existing.RiskKind = kind
		existing.RulesetVersion = rulesetVersion
		existing.LastSeen = item.LastSeen
		existing.UpdatedAt = now.Format(time.RFC3339Nano)
		existing.DedupeKey = dedupeKey
		// Shared exits and router observations are IP/device investigations in
		// this phase. Stale account-session blockers from the retired generic
		// proxy synchronizer must not be presented as a condition of this case.
		clearCaseIdentity(&existing)
		existing.EndpointID = item.EndpointID
		snapshot := newCaseEvidenceSnapshot(existing.CaseID, existing.RulesetVersion, item, now)
		snapshotExists := caseEvidenceSnapshotExists(existing.EvidenceHistory, snapshot.SnapshotID)
		if !snapshotExists && s.operations.tx != nil {
			if err := s.operations.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM risk_case_evidence_snapshots WHERE snapshot_id=$1)`, snapshot.SnapshotID).Scan(&snapshotExists); err != nil {
				return err
			}
		}
		if !snapshotExists {
			existing.EvidenceHistory = append(existing.EvidenceHistory, snapshot)
			if existing.EvidenceSnapshot.CaseID != "" {
				existing.Timeline = append(existing.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: "system", Type: "case.evidence_appended", Before: map[string]any{"risk_score": previousScore}, After: map[string]any{"risk_score": item.RiskScore, "snapshot_id": snapshot.SnapshotID}, CreatedAt: now.Format(time.RFC3339Nano)})
			}
		}
		existing.EvidenceSnapshot = item
		s.operations.doc.Cases[existing.CaseID] = existing
	}
	for caseID, existing := range s.operations.doc.Cases {
		kind := riskKindForRuleset(existing.RulesetVersion)
		if !closableKinds[kind] || existing.Status == "closed" || existing.Status == "resolved" || active[existing.DedupeKey] {
			continue
		}
		before := existing.Status
		existing.Status = "closed"
		existing.AssessmentCurrent = false
		existing.UpdatedAt = now.Format(time.RFC3339Nano)
		existing.Timeline = append(existing.Timeline, CaseTimeline{EventID: "timeline-" + shortToken(8), ActorID: "system", Type: "case.auto_closed_current_set", Before: map[string]any{"status": before}, After: map[string]any{"status": "closed"}, CreatedAt: now.Format(time.RFC3339Nano)})
		s.operations.doc.Cases[caseID] = existing
	}
	return s.operations.saveLocked()
}

func clearCaseIdentity(item *RiskCase) {
	item.AccountID, item.EndpointID, item.AuthSessionID = "", "", ""
	item.PersonType, item.Department, item.CampusID = "", "", ""
	item.BuildingID, item.NetworkZoneID, item.SSID = "", "", ""
	item.VLAN, item.AP, item.NASIP = "", "", ""
	item.IdentityConflict, item.IdentityBlocker = false, ""
}

func (s *Server) startCaseSynchronizer() {
	go func() {
		// Let the initial rolling risk materialization finish before consuming
		// snapshots left by a previous ruleset during an upgrade.
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			err := s.syncCasesContext(ctx, s.sensorID, "10m")
			cancel()
			if err != nil {
				s.operations.setCaseSyncHealthError(fmt.Errorf("automatic case synchronization: %w", err))
			} else {
				s.operations.setCaseSyncHealthError(nil)
			}
		}
	}()
}

func activeCaseMatches(candidate RiskCase, item store.ProxyReviewCase, dedupeKey string) bool {
	if candidate.Status == "closed" || candidate.Status == "resolved" {
		return false
	}
	if candidate.DedupeKey == dedupeKey {
		return true
	}
	// Evidence and protocol rules evolve while one investigation remains open.
	// Keep one active case per IP subject and append evidence history instead of
	// opening a second case merely because the evidence-derived key changed.
	return riskKindForRuleset(candidate.RulesetVersion) == caseRiskKind(item) && candidate.SubjectType == "ip" && (candidate.SubjectID == item.IP || candidate.IP == item.IP)
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
	identity := any(evidence)
	if evidence.RouterObservation != nil {
		components := make([]string, 0, len(evidence.RouterObservation.ScoreComponents))
		for _, component := range evidence.RouterObservation.ScoreComponents {
			components = append(components, component.EvidenceID)
		}
		sort.Strings(components)
		identity = struct {
			AssessmentID string   `json:"assessment_id"`
			Status       string   `json:"status"`
			Confidence   int      `json:"confidence"`
			RuleVersion  string   `json:"rule_version"`
			EvidenceIDs  []string `json:"evidence_ids"`
		}{evidence.RouterObservation.AssessmentID, evidence.RouterObservation.Status, evidence.RouterObservation.Confidence, evidence.RouterObservation.RuleVersion, components}
	}
	raw, _ := json.Marshal(identity)
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

// Cue grades describe protocol observations, not the combined risk estimate.
// Missing or invalid numeric estimates must never fabricate high confidence.
func caseRiskConfidence(item store.ProxyReviewCase) float64 {
	if item.SharedAccess != nil {
		return float64(item.SharedAccess.Confidence) / 100
	}
	if item.RouterObservation != nil {
		return float64(item.RouterObservation.Confidence) / 100
	}
	value := item.RiskConfidence
	if value == nil || math.IsNaN(*value) || *value < 0 || *value > 1 {
		return 0
	}
	return *value
}

func caseRiskKind(item store.ProxyReviewCase) string {
	if item.SharedAccess != nil {
		return "shared_access"
	}
	if item.RouterObservation != nil {
		return "router_observation"
	}
	return ""
}

func caseAssessmentLevel(item store.ProxyReviewCase) string {
	if item.RouterObservation != nil {
		return item.RouterObservation.Status
	}
	return item.RiskLevel
}

func caseRulesetVersion(item store.ProxyReviewCase) string {
	if item.RouterObservation != nil {
		return "router-observation/" + item.RouterObservation.RuleVersion
	}
	return sharedaccess.BehaviorRuleVersion
}

func riskKindForRuleset(rulesetVersion string) string {
	if strings.HasPrefix(rulesetVersion, "shared-behavior/") {
		return "shared_access"
	}
	if strings.HasPrefix(rulesetVersion, "router-observation/") {
		return "router_observation"
	}
	return ""
}

func proxyReviewCaseForSharedAssessment(assessment sharedaccess.BehaviorAssessment) store.ProxyReviewCase {
	scope := strings.Join([]string{assessment.SensorID, assessment.CampusID, assessment.AccessDomain, assessment.IP}, "\x00")
	sum := sha256.Sum256([]byte("shared-access-case\x00" + scope))
	anchorIdentities := make([]string, 0)
	for value := range assessment.FeatureSamples[assessment.StrongAnchor] {
		anchorIdentities = append(anchorIdentities, value)
	}
	sort.Strings(anchorIdentities)
	return store.ProxyReviewCase{
		CaseID: "shared-" + hex.EncodeToString(sum[:])[:20], IP: assessment.IP, EndpointID: assessment.EndpointID,
		AccessIDs: []string{}, Destinations: []store.ActivityCount{}, DestinationIPs: []store.ActivityCount{}, DestinationDomains: []store.ActivityCount{}, TLSFingerprints: []store.ActivityCount{}, Protocols: []store.ActivityCount{}, RuleMatches: []store.ProxyRuleMatch{},
		EventCount: len(assessment.EventIDs), ConfidenceLevel: "high", FirstSeen: assessment.FirstSeen.UTC().Format(time.RFC3339Nano), LastSeen: assessment.LastSeen.UTC().Format(time.RFC3339Nano), DurationSeconds: int64(assessment.WindowEnd.Sub(assessment.WindowStart).Seconds()), EvidenceIDs: []string{assessment.ObservationID}, RiskScore: assessment.Confidence, RiskLevel: "confirmed", ReviewStatus: "unreviewed",
		SharedAccess: &store.SharedAccessCaseEvidence{ObservationID: assessment.ObservationID, GenerationID: assessment.GenerationID, Status: assessment.Status, Confidence: assessment.Confidence, StrongAnchor: assessment.StrongAnchor, DeviceLowerBound: assessment.DeviceLowerBound, CoverageState: assessment.CoverageState, WindowStart: assessment.WindowStart.UTC().Format(time.RFC3339Nano), WindowEnd: assessment.WindowEnd.UTC().Format(time.RFC3339Nano), SignalGroups: append([]string{}, assessment.SignalGroups...), Reasons: append([]string{}, assessment.Reasons...), SourceEventIDs: append([]string{}, assessment.EventIDs...), AnchorIdentities: anchorIdentities, ReferenceDeviceCount24h: assessment.ReferenceDeviceCount24h, RouterBrand: assessment.Router.Brand, RouterModel: assessment.Router.Model, RouterConfidence: assessment.Router.Confidence},
	}
}

func proxyReviewCaseForRouterAssessment(assessment evidence.RouterAssessment) store.ProxyReviewCase {
	scope := firstNonEmptyString(assessment.AssessmentID, assessment.EndpointID, assessment.MAC, assessment.IP)
	sum := sha256.Sum256([]byte("router-observation-case\x00" + scope))
	evidenceIDs := make([]string, 0, len(assessment.ScoreComponents))
	for _, component := range assessment.ScoreComponents {
		if component.EvidenceID != "" {
			evidenceIDs = append(evidenceIDs, component.EvidenceID)
		}
	}
	sort.Strings(evidenceIDs)
	confidenceLevel, riskLevel := "medium", "suspicious"
	if assessment.Status == "confirmed" {
		confidenceLevel, riskLevel = "high", "confirmed"
	}
	return store.ProxyReviewCase{CaseID: "router-" + hex.EncodeToString(sum[:])[:20], IP: assessment.IP, EndpointID: assessment.EndpointID, AccessIDs: []string{}, Destinations: []store.ActivityCount{}, DestinationIPs: []store.ActivityCount{}, DestinationDomains: []store.ActivityCount{}, TLSFingerprints: []store.ActivityCount{}, Protocols: []store.ActivityCount{}, RuleMatches: []store.ProxyRuleMatch{}, ConfidenceLevel: confidenceLevel, FirstSeen: assessment.FirstSeen, LastSeen: assessment.LastSeen, EvidenceIDs: evidenceIDs, RiskScore: assessment.Confidence, RiskLevel: riskLevel, ReviewStatus: "unreviewed", RouterObservation: &assessment}
}

func (s *Server) handleCases(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/cases"), "/") == "" {
		if s.operations.db != nil {
			s.listCasesPostgres(w, r)
			return
		}
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
	if r.Method == http.MethodGet && len(parts) == 3 && parts[1] == "history" {
		if s.operations.db == nil {
			s.caseHistoryFile(w, r, caseID, parts[2])
		} else {
			s.caseHistoryPostgres(w, r, caseID, parts[2])
		}
		return
	}
	if r.Method == http.MethodGet && len(parts) == 1 {
		if s.operations.db != nil {
			s.getCasePostgres(w, r, caseID)
			return
		}
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
	includeRouterObservations := !strings.EqualFold(r.URL.Query().Get("include_router_observations"), "false")
	s.operations.mu.Lock()
	items := []RiskCase{}
	for _, item := range s.operations.doc.Cases {
		kind := riskKindForRuleset(item.RulesetVersion)
		if kind == "" || kind == "router_observation" && !includeRouterObservations || status == "" && (item.Status == "resolved" || item.Status == "closed") {
			continue
		}
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
	for index := range paged {
		paged[index] = s.projectFileCaseAssessment(paged[index])
	}
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
	writeJSON(w, 200, s.projectFileCaseAssessment(item))
}

func (s *Server) mutateCase(w http.ResponseWriter, r *http.Request, id, operation string) {
	if s.operations.db != nil && !s.operations.readView {
		s.mutateCasePostgres(w, r, id, operation)
		return
	}

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
	writeJSON(w, 200, s.projectMutatedCaseAssessment(item))
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
	if s.operations.db != nil {
		s.handleOrganizationPostgres(w, r)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/organization"), "/")
	s.operations.mu.Lock()
	if r.Method == http.MethodGet {
		kind := r.URL.Query().Get("kind")
		if kind != "" {
			limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
			if err != nil {
				s.operations.mu.Unlock()
				writeError(w, 400, "bad_page", err.Error())
				return
			}
			cursor, err := cursorOffset(r.URL.Query().Get("cursor"))
			if err != nil {
				s.operations.mu.Unlock()
				writeError(w, 400, "bad_page", err.Error())
				return
			}
			var response any
			switch kind {
			case "campuses":
				items, page := paginate(mapValues(s.operations.doc.Campuses), cursor, limit)
				response = map[string]any{"items": items, "page": page}
			case "buildings":
				items, page := paginate(mapValues(s.operations.doc.Buildings), cursor, limit)
				response = map[string]any{"items": items, "page": page}
			case "network_zones":
				items, page := paginate(mapValues(s.operations.doc.NetworkZones), cursor, limit)
				response = map[string]any{"items": items, "page": page}
			case "access_points":
				items, page := paginate(mapValues(s.operations.doc.AccessPoints), cursor, limit)
				response = map[string]any{"items": items, "page": page}
			default:
				s.operations.mu.Unlock()
				writeError(w, 400, "bad_organization_kind", "unknown organization kind")
				return
			}
			s.operations.mu.Unlock()
			writeJSON(w, 200, response)
			return
		}
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

func (s *Server) operationsSummary(ctx context.Context) (map[string]int, error) {
	if s.operations.db != nil {
		result := map[string]int{}
		var open, overdue, resolved int
		err := s.operations.db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE status NOT IN ('resolved','closed')),count(*) FILTER (WHERE status NOT IN ('resolved','closed') AND due_at<now()),count(*) FILTER (WHERE status IN ('resolved','closed')) FROM risk_cases`).Scan(&open, &overdue, &resolved)
		result["open"], result["overdue"], result["resolved"] = open, overdue, resolved
		return result, err
	}

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
	return result, nil
}

func validateOperationsPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("operations path is required")
	}
	return nil
}
