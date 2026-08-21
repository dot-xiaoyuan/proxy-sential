package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/evaluation"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

const (
	defaultDPIQueryLimit = 50000
	maxDPIQueryLimit     = 100000
)

type Options struct {
	Addr          string
	ShadowDir     string
	SensorID      string
	FrontendDir   string
	ReadOnly      bool
	StorageMode   string
	PostgresDSN   string
	ClickHouseDSN string
	CollectorKind string
	CollectorVer  string
	InterfaceName string
}

type Server struct {
	shadowDir   string
	sensorID    string
	frontendDir string
	readOnly    bool
	reader      store.Reader
}

type Session struct {
	User        User     `json:"user"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type RiskListResponse struct {
	Items []risk.Snapshot `json:"items"`
	Page  Page            `json:"page"`
}

type DeviceListResponse struct {
	Items []store.EndpointDeviceInventory `json:"items"`
	Page  Page                            `json:"page"`
}

type EventListResponse struct {
	Events []normalized.Event `json:"events"`
	Page   Page               `json:"page"`
}

type Page struct {
	Limit      int     `json:"limit"`
	NextCursor *string `json:"next_cursor"`
	Total      int     `json:"total"`
}

type ShadowRun struct {
	RunID          string `json:"run_id"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
	SensorID       string `json:"sensor_id"`
	PreviousOffset int64  `json:"previous_offset"`
	NewOffset      int64  `json:"new_offset"`
	Truncated      bool   `json:"truncated"`
	Normalized     any    `json:"normalized"`
	ZeekNormalized any    `json:"zeek_normalized,omitempty"`
	ZeekStatus     string `json:"zeek_status,omitempty"`
	ZeekReason     string `json:"zeek_reason,omitempty"`
	ZeekPrevOffset int64  `json:"zeek_previous_offset,omitempty"`
	ZeekNewOffset  int64  `json:"zeek_new_offset,omitempty"`
	ZeekTruncated  bool   `json:"zeek_truncated,omitempty"`
	EvidenceCount  int    `json:"evidence_count"`
	RiskCount      int    `json:"risk_count"`
	RiskListCount  int    `json:"risk_list_count"`
}

type Overview struct {
	LevelCounts     LevelCounts        `json:"level_counts"`
	PendingReviews  int                `json:"pending_reviews"`
	LatestShadowRun ShadowRun          `json:"latest_shadow_run"`
	Throughput      Throughput         `json:"throughput"`
	TopEvidence     []EvidenceTypeStat `json:"top_evidence"`
}

type LevelCounts struct {
	Normal     int `json:"normal"`
	Suspicious int `json:"suspicious"`
	High       int `json:"high"`
	Confirmed  int `json:"confirmed"`
}

type Throughput struct {
	Events   int `json:"events"`
	Evidence int `json:"evidence"`
	Risks    int `json:"risks"`
}

type EvidenceTypeStat struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type AuditLog struct {
	AuditID   string `json:"audit_id"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Outcome   string `json:"outcome"`
	CreatedAt string `json:"created_at"`
}

type RuleReloadResult struct {
	Status      string `json:"status"`
	Mode        string `json:"mode"`
	RequestedAt string `json:"requested_at"`
}

type CreateLabelRequest struct {
	TargetType  string   `json:"target_type"`
	TargetID    string   `json:"target_id"`
	Label       string   `json:"label"`
	Reason      string   `json:"reason"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type UpdateEndpointRegistrationRequest struct {
	RegistrationStatus   string `json:"registration_status"`
	OwnerAccount         string `json:"owner_account"`
	OwnerName            string `json:"owner_name"`
	OwnerDepartment      string `json:"owner_department"`
	AssetTag             string `json:"asset_tag"`
	RegistrationNote     string `json:"registration_note"`
	MergeStatus          string `json:"merge_status"`
	MergedIntoEndpointID string `json:"merged_into_endpoint_id"`
	SplitFromEndpointID  string `json:"split_from_endpoint_id"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func Serve(opts Options) error {
	addr := opts.Addr
	if addr == "" {
		addr = ":8080"
	}
	server, err := NewServerWithError(opts)
	if err != nil {
		return err
	}
	return http.ListenAndServe(addr, server.Handler())
}

func NewServer(opts Options) *Server {
	server, err := NewServerWithError(opts)
	if err == nil {
		return server
	}
	fallback := opts
	fallback.StorageMode = string(store.ModeFile)
	server, _ = NewServerWithError(fallback)
	return server
}

func NewServerWithError(opts Options) (*Server, error) {
	shadowDir := opts.ShadowDir
	if shadowDir == "" {
		shadowDir = "data/shadow"
	}
	sensorID := opts.SensorID
	if sensorID == "" {
		sensorID = "office-30"
	}
	mode := store.Mode(opts.StorageMode)
	if mode == "" {
		mode = store.ModeFile
	}
	reader, err := store.NewReader(store.Options{
		Mode:          mode,
		ShadowDir:     shadowDir,
		SensorID:      sensorID,
		CollectorKind: opts.CollectorKind,
		CollectorVer:  opts.CollectorVer,
		InterfaceName: opts.InterfaceName,
		PostgresDSN:   opts.PostgresDSN,
		ClickHouseDSN: opts.ClickHouseDSN,
	})
	if err != nil {
		return nil, err
	}
	return &Server{
		shadowDir:   shadowDir,
		sensorID:    sensorID,
		frontendDir: opts.FrontendDir,
		readOnly:    opts.ReadOnly,
		reader:      reader,
	}, nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if s.handleCORS(w, r) {
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1" {
		s.serveAPI(w, r)
		return
	}
	s.serveFrontend(w, r)
}

func (s *Server) handleCORS(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") && r.URL.Path != "/api/v1" {
		return false
	}
	addVary(w.Header(), "Origin")
	addVary(w.Header(), "Access-Control-Request-Method")
	addVary(w.Header(), "Access-Control-Request-Headers")
	origin := r.Header.Get("Origin")
	allowed := origin != "" && corsOriginAllowed(origin)
	if allowed {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	if r.Method != http.MethodOptions {
		return false
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "cors_forbidden", "cors origin is not allowed")
		return true
	}
	w.WriteHeader(http.StatusNoContent)
	return true
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case r.Method == http.MethodGet && path == "/session":
		writeJSON(w, http.StatusOK, s.session())
	case r.Method == http.MethodGet && path == "/overview":
		s.handleOverview(w, r)
	case r.Method == http.MethodGet && path == "/activity/overview":
		s.handleActivityOverview(w, r)
	case r.Method == http.MethodGet && path == "/proxy-reviews":
		s.handleProxyReviews(w, r)
	case r.Method == http.MethodGet && path == "/dpi/overview":
		s.handleDPIOverview(w, r)
	case r.Method == http.MethodGet && path == "/dpi/trends":
		s.handleDPITrends(w, r)
	case r.Method == http.MethodGet && path == "/dpi/protocol-flows":
		s.handleDPIProtocolFlows(w, r)
	case r.Method == http.MethodGet && path == "/dpi/fingerprint-conflicts":
		s.handleDPIFingerprintConflicts(w, r)
	case r.Method == http.MethodGet && path == "/dpi/flows":
		s.handleDPIFlows(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/dpi/flows/"):
		s.handleDPIFlow(w, r, strings.TrimPrefix(path, "/dpi/flows/"))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/dpi/ips/"):
		s.handleDPIIP(w, r, strings.TrimPrefix(path, "/dpi/ips/"))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/accounts/"):
		s.handleAccount(w, r, strings.TrimPrefix(path, "/accounts/"))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/endpoints/"):
		s.handleEndpoint(w, r, strings.TrimPrefix(path, "/endpoints/"))
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/endpoints/"):
		s.handleEndpointRegistration(w, r, strings.TrimPrefix(path, "/endpoints/"))
	case r.Method == http.MethodGet && path == "/devices":
		s.handleDevices(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/devices/"):
		s.handleDevice(w, r, strings.TrimPrefix(path, "/devices/"))
	case r.Method == http.MethodGet && path == "/device-signals":
		s.handleDeviceSignals(w, r)
	case r.Method == http.MethodGet && path == "/device-fingerprint-conflicts":
		s.handleDeviceFingerprintConflicts(w, r)
	case r.Method == http.MethodGet && path == "/risks":
		s.handleRisks(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/ips/"):
		s.handleIP(w, r, strings.TrimPrefix(path, "/ips/"))
	case r.Method == http.MethodGet && path == "/events":
		s.handleEvents(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/events/"):
		s.handleEvent(w, r, strings.TrimPrefix(path, "/events/"))
	case r.Method == http.MethodGet && path == "/ingest/status":
		s.handleIngestStatus(w, r)
	case r.Method == http.MethodGet && path == "/ingest/runs":
		s.handleShadowRuns(w, r)
	case r.Method == http.MethodGet && path == "/ingest/diagnostics":
		s.handleIngestDiagnostics(w, r)
	case r.Method == http.MethodGet && path == "/ingest/event-types":
		s.handleIngestEventTypes(w, r)
	case r.Method == http.MethodGet && path == "/ingest/errors":
		s.handleIngestErrors(w, r)
	case r.Method == http.MethodGet && path == "/shadow/runs":
		s.handleShadowRuns(w, r)
	case r.Method == http.MethodGet && path == "/shadow/evaluation":
		s.handleShadowEvaluation(w, r)
	case r.Method == http.MethodGet && path == "/audit-logs":
		s.handleAuditLogs(w, r)
	case r.Method == http.MethodPost && path == "/rules/reload":
		writeJSON(w, http.StatusAccepted, RuleReloadResult{
			Status:      "disabled",
			Mode:        "shadow",
			RequestedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
	case r.Method == http.MethodPost && path == "/labels":
		s.handleCreateLabel(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "api endpoint not found")
	}
}

func (s *Server) handleProxyReviews(w http.ResponseWriter, r *http.Request) {
	window := strings.TrimSpace(r.URL.Query().Get("window"))
	if window == "" {
		window = "7d"
	}
	if _, _, err := store.NormalizeActivityWindow(window); err != nil {
		writeError(w, http.StatusBadRequest, "bad_proxy_review_window", err.Error())
		return
	}
	limit, err := boundedInt(r.URL.Query().Get("limit"), defaultDPIQueryLimit, 1, maxDPIQueryLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	result, err := s.reader.GetProxyReviews(ctx, store.ActivityQuery{
		SensorID: r.URL.Query().Get("sensor_id"),
		Window:   window,
		Limit:    limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_proxy_reviews_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) serveFrontend(w http.ResponseWriter, r *http.Request) {
	if s.frontendDir == "" {
		writeError(w, http.StatusNotFound, "not_found", "frontend directory is not configured")
		return
	}
	clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if clean == "." {
		clean = "index.html"
	}
	target := filepath.Join(s.frontendDir, clean)
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		http.ServeFile(w, r, target)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.frontendDir, "index.html"))
}

func (s *Server) session() Session {
	permissions := []string{"risks:read", "evidence:read", "events:read", "shadow:read", "audit:read", "ingest:read", "dpi:read"}
	user := User{ID: "shadow-viewer", Name: "影子观测只读用户"}
	if !s.readOnly {
		permissions = append(permissions, "labels:create", "endpoints:write", "rules:reload")
		user = User{ID: "shadow-operator", Name: "影子运营复核员"}
	}
	return Session{
		User:        user,
		Role:        "viewer",
		Permissions: permissions,
	}
}

func (s *Server) handleCreateLabel(w http.ResponseWriter, r *http.Request) {
	if s.readOnly {
		writeError(w, http.StatusForbidden, "read_only", "labels are disabled in read-only control plane mode")
		return
	}
	var request CreateLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_label_request", err.Error())
		return
	}
	if err := validateLabelRequest(request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_label_request", err.Error())
		return
	}
	label := store.Label{
		TargetType:  request.TargetType,
		TargetID:    request.TargetID,
		Label:       request.Label,
		Reason:      strings.TrimSpace(request.Reason),
		EvidenceIDs: request.EvidenceIDs,
		CreatedBy:   s.session().User.ID,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	created, err := s.reader.CreateLabel(ctx, label)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create_label_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, rest string) {
	if !strings.HasSuffix(rest, "/identity") {
		writeError(w, http.StatusNotFound, "not_found", "account endpoint not found")
		return
	}
	rawAccountID := strings.TrimSuffix(rest, "/identity")
	accountID, err := store.DecodePathIP(rawAccountID)
	if err != nil || strings.TrimSpace(accountID) == "" {
		writeError(w, http.StatusBadRequest, "bad_account_id", "account id is required")
		return
	}
	query, err := identityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_identity_query", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	profile, ok, err := s.reader.GetAccountIdentity(ctx, accountID, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_account_identity_failed", err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "account_identity_not_found", "account identity profile not found")
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Server) handleEndpoint(w http.ResponseWriter, r *http.Request, rest string) {
	if !strings.HasSuffix(rest, "/identity") {
		writeError(w, http.StatusNotFound, "not_found", "endpoint endpoint not found")
		return
	}
	rawEndpointID := strings.TrimSuffix(rest, "/identity")
	endpointID, err := store.DecodePathIP(rawEndpointID)
	if err != nil || strings.TrimSpace(endpointID) == "" {
		writeError(w, http.StatusBadRequest, "bad_endpoint_id", "endpoint id is required")
		return
	}
	query, err := identityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_identity_query", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	profile, ok, err := s.reader.GetEndpointIdentity(ctx, endpointID, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_endpoint_identity_failed", err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "endpoint_identity_not_found", "endpoint identity profile not found")
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Server) handleEndpointRegistration(w http.ResponseWriter, r *http.Request, rest string) {
	if s.readOnly {
		writeError(w, http.StatusForbidden, "read_only", "endpoint registration is disabled in read-only control plane mode")
		return
	}
	if !strings.HasSuffix(rest, "/registration") {
		writeError(w, http.StatusNotFound, "not_found", "endpoint endpoint not found")
		return
	}
	endpointID, err := store.DecodePathIP(strings.TrimSuffix(rest, "/registration"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_endpoint_id", err.Error())
		return
	}
	var request UpdateEndpointRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_endpoint_registration_request", err.Error())
		return
	}
	if err := validateEndpointRegistrationRequest(endpointID, request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_endpoint_registration_request", err.Error())
		return
	}
	update := store.EndpointRegistrationUpdate{
		EndpointID:            endpointID,
		RegistrationStatus:    strings.TrimSpace(request.RegistrationStatus),
		OwnerAccount:          strings.TrimSpace(request.OwnerAccount),
		OwnerName:             strings.TrimSpace(request.OwnerName),
		OwnerDepartment:       strings.TrimSpace(request.OwnerDepartment),
		AssetTag:              strings.TrimSpace(request.AssetTag),
		RegistrationNote:      strings.TrimSpace(request.RegistrationNote),
		MergeStatus:           strings.TrimSpace(request.MergeStatus),
		MergedIntoEndpointID:  strings.TrimSpace(request.MergedIntoEndpointID),
		SplitFromEndpointID:   strings.TrimSpace(request.SplitFromEndpointID),
		RegistrationUpdatedBy: s.session().User.ID,
		RegistrationUpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	endpoint, err := s.reader.UpdateEndpointRegistration(ctx, update)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update_endpoint_registration_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, endpoint)
}

func validateLabelRequest(request CreateLabelRequest) error {
	switch request.TargetType {
	case "ip", "risk_snapshot", "evidence", "account", "endpoint":
	default:
		return fmt.Errorf("unsupported target_type: %s", request.TargetType)
	}
	if strings.TrimSpace(request.TargetID) == "" {
		return fmt.Errorf("target_id is required")
	}
	switch request.Label {
	case "confirmed_proxy", "false_positive", "benign", "needs_more_data":
	default:
		return fmt.Errorf("unsupported label: %s", request.Label)
	}
	if len(strings.TrimSpace(request.Reason)) < 2 {
		return fmt.Errorf("reason must contain at least 2 characters")
	}
	if len(request.EvidenceIDs) == 0 {
		return fmt.Errorf("evidence_ids must contain at least one evidence id")
	}
	return nil
}

func validateEndpointRegistrationRequest(endpointID string, request UpdateEndpointRegistrationRequest) error {
	if strings.TrimSpace(endpointID) == "" {
		return fmt.Errorf("endpoint_id is required")
	}
	switch request.RegistrationStatus {
	case "unregistered", "registered", "ignored", "retired":
	default:
		return fmt.Errorf("unsupported registration_status: %s", request.RegistrationStatus)
	}
	switch request.MergeStatus {
	case "", "active", "merged", "split":
	default:
		return fmt.Errorf("unsupported merge_status: %s", request.MergeStatus)
	}
	if request.RegistrationStatus == "registered" && strings.TrimSpace(request.OwnerAccount) == "" && strings.TrimSpace(request.OwnerName) == "" && strings.TrimSpace(request.AssetTag) == "" {
		return fmt.Errorf("registered endpoint requires owner_account, owner_name or asset_tag")
	}
	if request.MergeStatus == "merged" && strings.TrimSpace(request.MergedIntoEndpointID) == "" {
		return fmt.Errorf("merged endpoint requires merged_into_endpoint_id")
	}
	if strings.TrimSpace(request.MergedIntoEndpointID) == strings.TrimSpace(endpointID) {
		return fmt.Errorf("merged_into_endpoint_id cannot equal endpoint_id")
	}
	return nil
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	overview, err := s.reader.Overview(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_overview_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, Overview{
		LevelCounts: LevelCounts{
			Normal:     overview.LevelCounts["normal"],
			Suspicious: overview.LevelCounts["suspicious"],
			High:       overview.LevelCounts["high"],
			Confirmed:  overview.LevelCounts["confirmed"],
		},
		PendingReviews:  overview.PendingReviews,
		LatestShadowRun: toShadowRun(overview.LatestRun),
		Throughput: Throughput{
			Events:   overview.Throughput["events"],
			Evidence: overview.Throughput["evidence"],
			Risks:    overview.Throughput["risks"],
		},
		TopEvidence: toEvidenceTypeStats(overview.TopEvidence),
	})
}

func (s *Server) handleRisks(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	cursor, err := cursorOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_cursor", err.Error())
		return
	}
	page, err := s.reader.ListRisks(r.Context(), store.Query{
		Level:    r.URL.Query().Get("level"),
		Q:        r.URL.Query().Get("q"),
		SensorID: r.URL.Query().Get("sensor_id"),
		From:     r.URL.Query().Get("from"),
		To:       r.URL.Query().Get("to"),
		Limit:    limit,
		Cursor:   cursor,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_risk_query", err.Error())
		return
	}
	s.enrichRiskDevices(r.Context(), page.Items)
	writeJSON(w, http.StatusOK, RiskListResponse{Items: page.Items, Page: Page{Limit: page.Page.Limit, NextCursor: page.Page.NextCursor, Total: page.Page.Total}})
}

func (s *Server) handleIP(w http.ResponseWriter, r *http.Request, rest string) {
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/risk"):
		ip, err := pathIP(strings.TrimSuffix(rest, "/risk"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_ip", err.Error())
			return
		}
		s.handleIPRisk(w, r, ip)
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/evidence"):
		ip, err := pathIP(strings.TrimSuffix(rest, "/evidence"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_ip", err.Error())
			return
		}
		s.handleIPEvidence(w, r, ip)
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/activity"):
		ip, err := pathIP(strings.TrimSuffix(rest, "/activity"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_ip", err.Error())
			return
		}
		s.handleIPActivity(w, r, ip)
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/devices"):
		ip, err := pathIP(strings.TrimSuffix(rest, "/devices"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_ip", err.Error())
			return
		}
		s.handleIPDevices(w, r, ip)
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/events"):
		ip, err := pathIP(strings.TrimSuffix(rest, "/events"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_ip", err.Error())
			return
		}
		s.handleIPEvents(w, r, ip)
	default:
		writeError(w, http.StatusNotFound, "not_found", "ip endpoint not found")
	}
}

func (s *Server) handleIPRisk(w http.ResponseWriter, r *http.Request, ip string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	snapshot, err := s.reader.GetIPRisk(ctx, ip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_risks_failed", err.Error())
		return
	}
	s.enrichRiskDevice(ctx, &snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleIPEvidence(w http.ResponseWriter, r *http.Request, ip string) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	items, err := s.reader.GetIPEvidence(ctx, ip, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_evidence_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"evidence": items})
}

func (s *Server) handleIPActivity(w http.ResponseWriter, r *http.Request, ip string) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	profile, err := s.reader.GetIPActivity(ctx, ip, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_activity_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Server) handleIPDevices(w http.ResponseWriter, r *http.Request, ip string) {
	query, err := s.deviceActivityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_device_query", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	inventory, err := s.reader.GetIPDeviceInventory(ctx, ip, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_ip_devices_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	query, err := deviceQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_device_query", err.Error())
		return
	}
	if query.SensorID == "" {
		query.SensorID = s.sensorID
	}
	if r.URL.Query().Get("window") == "" {
		query.Window = ""
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	page, err := s.reader.ListEndpointDevices(ctx, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_devices_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, DeviceListResponse{Items: page.Items, Page: Page{Limit: page.Page.Limit, NextCursor: page.Page.NextCursor, Total: page.Page.Total}})
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request, rawDeviceID string) {
	deviceID, err := store.DecodePathIP(rawDeviceID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_device_id", err.Error())
		return
	}
	query, err := deviceQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_device_query", err.Error())
		return
	}
	if query.SensorID == "" {
		query.SensorID = s.sensorID
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	device, ok, err := s.reader.GetDevice(ctx, deviceID, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_device_failed", err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "device_not_found", "device candidate not found")
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (s *Server) handleDeviceSignals(w http.ResponseWriter, r *http.Request) {
	query, err := deviceQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_device_query", err.Error())
		return
	}
	if query.SensorID == "" {
		query.SensorID = s.sensorID
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	items, err := s.reader.ListDeviceSignals(ctx, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_device_signals_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleDeviceFingerprintConflicts(w http.ResponseWriter, r *http.Request) {
	query, err := deviceQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_device_query", err.Error())
		return
	}
	if query.SensorID == "" {
		query.SensorID = s.sensorID
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	items, err := s.reader.ListDeviceFingerprintConflicts(ctx, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_device_conflicts_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleActivityOverview(w http.ResponseWriter, r *http.Request) {
	sensorID := r.URL.Query().Get("sensor_id")
	if sensorID == "" {
		sensorID = s.sensorID
	}
	window := r.URL.Query().Get("window")
	if _, _, err := store.NormalizeActivityWindow(window); err != nil {
		writeError(w, http.StatusBadRequest, "bad_activity_window", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	overview, err := s.reader.GetActivityOverview(ctx, store.ActivityQuery{
		SensorID: sensorID,
		Window:   window,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_activity_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleDPIOverview(w http.ResponseWriter, r *http.Request) {
	query, err := s.activityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_dpi_query", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	overview, err := s.reader.GetDPIOverview(ctx, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_dpi_overview_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleDPITrends(w http.ResponseWriter, r *http.Request) {
	query, err := s.activityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_dpi_query", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	items, err := s.reader.ListDPITrends(ctx, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_dpi_trends_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": items})
}

func (s *Server) handleDPIProtocolFlows(w http.ResponseWriter, r *http.Request) {
	query, err := s.activityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_dpi_query", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	items, err := s.reader.ListDPIProtocolFlows(ctx, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_dpi_protocol_flows_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleDPIFingerprintConflicts(w http.ResponseWriter, r *http.Request) {
	query, err := s.activityQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_dpi_query", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	items, err := s.reader.ListDPIFingerprintConflicts(ctx, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_dpi_fingerprint_conflicts_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleDPIFlows(w http.ResponseWriter, r *http.Request) {
	query, err := eventQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_dpi_flow_query", err.Error())
		return
	}
	if query.SensorID == "" {
		query.SensorID = s.sensorID
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	page, err := s.reader.ListDPIFlows(ctx, query)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_dpi_flow_query", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleDPIFlow(w http.ResponseWriter, r *http.Request, rawFlowID string) {
	flowID, err := store.DecodePathIP(rawFlowID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_flow_id", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	detail, ok, err := s.reader.GetDPIFlow(ctx, flowID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_dpi_flow_failed", err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "dpi flow not found")
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleDPIIP(w http.ResponseWriter, r *http.Request, rest string) {
	if !strings.HasSuffix(rest, "/flows") {
		writeError(w, http.StatusNotFound, "not_found", "dpi ip endpoint not found")
		return
	}
	ip, err := pathIP(strings.TrimSuffix(rest, "/flows"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_ip", err.Error())
		return
	}
	query, err := eventQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_dpi_flow_query", err.Error())
		return
	}
	if query.SensorID == "" {
		query.SensorID = s.sensorID
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	page, err := s.reader.ListIPDPIFlows(ctx, ip, query)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_dpi_flow_query", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleIPEvents(w http.ResponseWriter, r *http.Request, ip string) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	events, err := s.reader.ListEventSamples(r.Context(), store.Query{SrcIP: ip, Limit: limit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_events_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleShadowRuns(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	runs, err := s.reader.ListRuns(ctx, 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_shadow_runs_failed", err.Error())
		return
	}
	items := make([]ShadowRun, 0, len(runs))
	for _, run := range runs {
		items = append(items, toShadowRun(run))
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": items})
}

func (s *Server) handleShadowEvaluation(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.shadowDir, "evaluation", "latest.json")
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "shadow_evaluation_not_found", "shadow evaluation has not been generated yet")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_shadow_evaluation_failed", err.Error())
		return
	}
	defer file.Close()
	var report evaluation.ShadowEvaluationReport
	if err := json.NewDecoder(file).Decode(&report); err != nil {
		writeError(w, http.StatusInternalServerError, "decode_shadow_evaluation_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	logs, err := s.reader.ListAuditLogs(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_audit_logs_failed", err.Error())
		return
	}
	items := make([]AuditLog, 0, len(logs))
	for _, log := range logs {
		items = append(items, AuditLog{
			AuditID:   log.AuditID,
			Actor:     log.Actor,
			Action:    log.Action,
			Target:    log.Target,
			Outcome:   log.Outcome,
			CreatedAt: log.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": items})
}

func (s *Server) handleIngestStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.reader.IngestStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_ingest_status_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleIngestDiagnostics(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	items, err := s.reader.ListIngestDiagnostics(r.Context(), store.Query{Limit: limit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_ingest_diagnostics_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"diagnostics": items})
}

func (s *Server) handleIngestEventTypes(w http.ResponseWriter, r *http.Request) {
	items, err := s.reader.ListIngestEventTypes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_ingest_event_types_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"event_types": items})
}

func (s *Server) handleIngestErrors(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	items, err := s.reader.ListIngestErrors(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_ingest_errors_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"diagnostics": items})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	query, err := eventQuery(r.URL.Query())
	if err != nil {
		writeEventQueryError(w, err)
		return
	}
	page, err := s.reader.ListEvents(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_event_query", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, EventListResponse{
		Events: page.Items,
		Page:   Page{Limit: page.Page.Limit, NextCursor: page.Page.NextCursor, Total: page.Page.Total},
	})
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request, rawEventID string) {
	eventID, err := store.DecodePathIP(rawEventID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_event_id", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	event, ok, err := s.reader.GetEvent(ctx, eventID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_event_failed", err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "event not found")
		return
	}
	writeJSON(w, http.StatusOK, event)
}

func (s *Server) activityQuery(values url.Values) (store.ActivityQuery, error) {
	sensorID := values.Get("sensor_id")
	if sensorID == "" {
		sensorID = s.sensorID
	}
	window := values.Get("window")
	if _, _, err := store.NormalizeActivityWindow(window); err != nil {
		return store.ActivityQuery{}, err
	}
	limit, err := boundedInt(values.Get("limit"), defaultDPIQueryLimit, 1, maxDPIQueryLimit)
	if err != nil {
		return store.ActivityQuery{}, err
	}
	return store.ActivityQuery{SensorID: sensorID, Window: window, Limit: limit}, nil
}

func (s *Server) deviceActivityQuery(values url.Values) (store.ActivityQuery, error) {
	sensorID := values.Get("sensor_id")
	if sensorID == "" {
		sensorID = s.sensorID
	}
	window := values.Get("window")
	if window == "" {
		window = "1h"
	}
	if _, _, err := store.NormalizeActivityWindow(window); err != nil {
		return store.ActivityQuery{}, err
	}
	return store.ActivityQuery{SensorID: sensorID, Window: window, Limit: defaultDPIQueryLimit}, nil
}

func deviceQuery(values url.Values) (store.Query, error) {
	limit, err := boundedInt(values.Get("limit"), 50, 1, 200)
	if err != nil {
		return store.Query{}, fmt.Errorf("bad limit: %w", err)
	}
	cursor, err := cursorOffset(values.Get("cursor"))
	if err != nil {
		return store.Query{}, fmt.Errorf("bad cursor: %w", err)
	}
	window := values.Get("window")
	if window == "" {
		window = "1h"
	}
	if _, _, err := store.NormalizeActivityWindow(window); err != nil {
		return store.Query{}, fmt.Errorf("bad window: %w", err)
	}
	return store.Query{
		Q:           values.Get("q"),
		SensorID:    values.Get("sensor_id"),
		Window:      window,
		SrcIP:       values.Get("ip"),
		Limit:       limit,
		Cursor:      cursor,
		IncludeWeak: values.Get("include_weak") == "true" || values.Get("include_weak") == "1",
	}, nil
}

func identityQuery(values url.Values) (store.Query, error) {
	limit, err := boundedInt(values.Get("limit"), 200, 1, 1000)
	if err != nil {
		return store.Query{}, fmt.Errorf("bad limit: %w", err)
	}
	window := values.Get("window")
	if window != "" {
		if _, _, err := store.NormalizeActivityWindow(window); err != nil {
			return store.Query{}, fmt.Errorf("bad window: %w", err)
		}
	}
	return store.Query{
		SensorID: values.Get("sensor_id"),
		From:     values.Get("from"),
		To:       values.Get("to"),
		Window:   window,
		Limit:    limit,
	}, nil
}

func (s *Server) enrichRiskDevices(ctx context.Context, items []risk.Snapshot) {
	if len(items) == 0 {
		return
	}
	page, err := s.reader.ListDeviceInventories(ctx, store.Query{SensorID: s.sensorID, Window: "1h", Limit: -1, IncludeWeak: true})
	if err == nil {
		byIP := make(map[string]store.IPDeviceInventory, len(page.Items))
		for _, inventory := range page.Items {
			byIP[inventory.IP] = inventory
		}
		for index := range items {
			if inventory, ok := byIP[items[index].IP]; ok {
				applyRiskDeviceInventory(&items[index], inventory)
			}
		}
		return
	}
	for index := range items {
		s.enrichRiskDevice(ctx, &items[index])
	}
}

func (s *Server) enrichRiskDevice(ctx context.Context, snapshot *risk.Snapshot) {
	if snapshot == nil || snapshot.IP == "" {
		return
	}
	inventory, err := s.reader.GetIPDeviceInventory(ctx, snapshot.IP, store.ActivityQuery{SensorID: s.sensorID, Window: "1h", Limit: defaultDPIQueryLimit})
	if err != nil {
		return
	}
	applyRiskDeviceInventory(snapshot, inventory)
}

func applyRiskDeviceInventory(snapshot *risk.Snapshot, inventory store.IPDeviceInventory) {
	snapshot.SuspectedDeviceCount = inventory.SuspectedDeviceCount
	snapshot.DeviceSummary = inventory.Summary
	snapshot.DeviceConfidence = inventory.Confidence
}

func eventQuery(values url.Values) (store.Query, error) {
	limit, err := boundedInt(values.Get("limit"), 50, 1, 200)
	if err != nil {
		return store.Query{}, fmt.Errorf("bad limit: %w", err)
	}
	cursor, err := cursorOffset(values.Get("cursor"))
	if err != nil {
		return store.Query{}, fmt.Errorf("bad cursor: %w", err)
	}
	port, err := optionalBoundedInt(values.Get("port"), 1, 65535)
	if err != nil {
		return store.Query{}, fmt.Errorf("bad port: %w", err)
	}
	return store.Query{
		Q:           values.Get("q"),
		Level:       values.Get("type"),
		SensorID:    values.Get("sensor_id"),
		From:        values.Get("from"),
		To:          values.Get("to"),
		Window:      values.Get("window"),
		SrcIP:       values.Get("src_ip"),
		DstIP:       values.Get("dst_ip"),
		Domain:      values.Get("domain"),
		UserAgent:   values.Get("user_agent"),
		Fingerprint: values.Get("fingerprint"),
		Port:        port,
		Proto:       values.Get("proto"),
		Limit:       limit,
		Cursor:      cursor,
	}, nil
}

func contextWithRequestTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 10*time.Second)
}

func toShadowRun(run store.Run) ShadowRun {
	return ShadowRun{
		RunID:          run.RunID,
		StartedAt:      run.StartedAt,
		FinishedAt:     run.FinishedAt,
		SensorID:       run.SensorID,
		PreviousOffset: run.PreviousOffset,
		NewOffset:      run.NewOffset,
		Truncated:      run.Truncated,
		Normalized:     normalizedCounts{Read: run.Normalized.Read, Emitted: run.Normalized.Emitted, Skipped: run.Normalized.Skipped, Malformed: run.Normalized.Malformed, ByType: run.Normalized.ByType},
		ZeekNormalized: optionalNormalizedCounts(run.ZeekNormalized),
		ZeekStatus:     run.ZeekStatus,
		ZeekReason:     run.ZeekReason,
		ZeekPrevOffset: run.ZeekPrevOffset,
		ZeekNewOffset:  run.ZeekNewOffset,
		ZeekTruncated:  run.ZeekTruncated,
		EvidenceCount:  run.EvidenceCount,
		RiskCount:      run.RiskCount,
		RiskListCount:  run.RiskListCount,
	}
}

type normalizedCounts struct {
	Read      int            `json:"read"`
	Emitted   int            `json:"emitted"`
	Skipped   int            `json:"skipped"`
	Malformed int            `json:"malformed"`
	ByType    map[string]int `json:"by_type,omitempty"`
}

func optionalNormalizedCounts(counts store.NormalizedCounts) any {
	if counts.Read == 0 && counts.Emitted == 0 && counts.Skipped == 0 && counts.Malformed == 0 && len(counts.ByType) == 0 {
		return nil
	}
	return normalizedCounts{Read: counts.Read, Emitted: counts.Emitted, Skipped: counts.Skipped, Malformed: counts.Malformed, ByType: counts.ByType}
}

func toEvidenceTypeStats(items []ingest.EventTypeCount) []EvidenceTypeStat {
	result := make([]EvidenceTypeStat, 0, len(items))
	for _, item := range items {
		result = append(result, EvidenceTypeStat{Type: item.Type, Count: item.Count})
	}
	return result
}

func boundedInt(raw string, defaultValue, minValue, maxValue int) (int, error) {
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("must be an integer")
	}
	if value < minValue || value > maxValue {
		return 0, fmt.Errorf("must be between %d and %d", minValue, maxValue)
	}
	return value, nil
}

func optionalBoundedInt(raw string, minValue, maxValue int) (int, error) {
	if raw == "" {
		return 0, nil
	}
	return boundedInt(raw, 0, minValue, maxValue)
}

func cursorOffset(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("cursor must be a non-negative integer offset")
	}
	return value, nil
}

func pathIP(raw string) (string, error) {
	return store.DecodePathIP(raw)
}

func corsOriginAllowed(origin string) bool {
	if configuredCORSOriginAllowed(origin) {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	switch parsed.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return parsed.Scheme == "http" || parsed.Scheme == "https"
	default:
		return false
	}
}

func configuredCORSOriginAllowed(origin string) bool {
	for _, item := range strings.Split(os.Getenv("PROXY_SENTINEL_CORS_ORIGINS"), ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if item == "*" || strings.TrimRight(item, "/") == origin {
			return true
		}
	}
	return false
}

func addVary(header http.Header, value string) {
	existing := header.Values("Vary")
	for _, line := range existing {
		for _, item := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(item), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, ErrorResponse{Code: code, Message: message})
}

func writeEventQueryError(w http.ResponseWriter, err error) {
	message := err.Error()
	switch {
	case strings.HasPrefix(message, "bad limit:"):
		writeError(w, http.StatusBadRequest, "bad_limit", strings.TrimSpace(strings.TrimPrefix(message, "bad limit:")))
	case strings.HasPrefix(message, "bad cursor:"):
		writeError(w, http.StatusBadRequest, "bad_cursor", strings.TrimSpace(strings.TrimPrefix(message, "bad cursor:")))
	case strings.HasPrefix(message, "bad port:"):
		writeError(w, http.StatusBadRequest, "bad_port", strings.TrimSpace(strings.TrimPrefix(message, "bad port:")))
	default:
		writeError(w, http.StatusBadRequest, "bad_event_query", message)
	}
}
