package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
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
	if strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1" {
		s.serveAPI(w, r)
		return
	}
	s.serveFrontend(w, r)
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case r.Method == http.MethodGet && path == "/session":
		writeJSON(w, http.StatusOK, s.session())
	case r.Method == http.MethodGet && path == "/overview":
		s.handleOverview(w, r)
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
	case r.Method == http.MethodGet && path == "/audit-logs":
		s.handleAuditLogs(w, r)
	case r.Method == http.MethodPost && path == "/rules/reload":
		writeJSON(w, http.StatusAccepted, RuleReloadResult{
			Status:      "disabled",
			Mode:        "shadow",
			RequestedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
	case r.Method == http.MethodPost && path == "/labels":
		writeError(w, http.StatusForbidden, "read_only", "labels are disabled in read-only control plane mode")
	default:
		writeError(w, http.StatusNotFound, "not_found", "api endpoint not found")
	}
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
	permissions := []string{"risks:read", "evidence:read", "events:read", "shadow:read", "audit:read", "ingest:read"}
	return Session{
		User:        User{ID: "shadow-viewer", Name: "影子观测只读用户"},
		Role:        "viewer",
		Permissions: permissions,
	}
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
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleIPEvidence(w http.ResponseWriter, r *http.Request, ip string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	items, err := s.reader.GetIPEvidence(ctx, ip)
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

func (s *Server) handleIPEvents(w http.ResponseWriter, r *http.Request, ip string) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	events, err := s.reader.ListEventSamples(r.Context(), store.Query{Q: ip, Limit: limit})
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
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	events, err := s.reader.ListEventSamples(r.Context(), store.Query{
		Q:        r.URL.Query().Get("q"),
		Level:    r.URL.Query().Get("type"),
		SensorID: r.URL.Query().Get("sensor_id"),
		Limit:    limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_events_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
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
		Normalized:     normalizedCounts{Read: run.Normalized.Read, Emitted: run.Normalized.Emitted, Skipped: run.Normalized.Skipped, Malformed: run.Normalized.Malformed},
		EvidenceCount:  run.EvidenceCount,
		RiskCount:      run.RiskCount,
		RiskListCount:  run.RiskListCount,
	}
}

type normalizedCounts struct {
	Read      int `json:"read"`
	Emitted   int `json:"emitted"`
	Skipped   int `json:"skipped"`
	Malformed int `json:"malformed"`
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
