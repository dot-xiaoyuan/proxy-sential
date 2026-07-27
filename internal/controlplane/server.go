package controlplane

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/shadow"
)

type Options struct {
	Addr        string
	ShadowDir   string
	SensorID    string
	FrontendDir string
	ReadOnly    bool
}

type Server struct {
	shadowDir   string
	sensorID    string
	frontendDir string
	readOnly    bool
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

type runRecord struct {
	ID      string
	Dir     string
	Summary shadow.RunSummary
	Started time.Time
}

func Serve(opts Options) error {
	addr := opts.Addr
	if addr == "" {
		addr = ":8080"
	}
	server := NewServer(opts)
	return http.ListenAndServe(addr, server.Handler())
}

func NewServer(opts Options) *Server {
	shadowDir := opts.ShadowDir
	if shadowDir == "" {
		shadowDir = "data/shadow"
	}
	sensorID := opts.SensorID
	if sensorID == "" {
		sensorID = "office-30"
	}
	return &Server{
		shadowDir:   shadowDir,
		sensorID:    sensorID,
		frontendDir: opts.FrontendDir,
		readOnly:    opts.ReadOnly,
	}
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
		s.handleOverview(w)
	case r.Method == http.MethodGet && path == "/risks":
		s.handleRisks(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/ips/"):
		s.handleIP(w, r, strings.TrimPrefix(path, "/ips/"))
	case r.Method == http.MethodGet && path == "/shadow/runs":
		s.handleShadowRuns(w)
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
	permissions := []string{"risks:read", "evidence:read", "events:read", "shadow:read", "audit:read"}
	return Session{
		User:        User{ID: "shadow-viewer", Name: "影子观测只读用户"},
		Role:        "viewer",
		Permissions: permissions,
	}
}

func (s *Server) handleOverview(w http.ResponseWriter) {
	latest, ok, err := s.latestRun()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_shadow_runs_failed", err.Error())
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, Overview{
			LevelCounts:     LevelCounts{},
			PendingReviews:  0,
			LatestShadowRun: ShadowRun{SensorID: s.sensorID, Normalized: normalizedCounts{}},
			Throughput:      Throughput{},
			TopEvidence:     []EvidenceTypeStat{},
		})
		return
	}

	batch, err := readRiskBatch(filepath.Join(latest.Dir, "risk-snapshots.json"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_risks_failed", err.Error())
		return
	}
	evidenceResult, err := readEvidence(filepath.Join(latest.Dir, "evidence.json"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_evidence_failed", err.Error())
		return
	}

	counts := levelCounts(batch.Snapshots)
	writeJSON(w, http.StatusOK, Overview{
		LevelCounts:     counts,
		PendingReviews:  counts.High + counts.Confirmed,
		LatestShadowRun: s.toShadowRun(latest),
		Throughput: Throughput{
			Events:   latest.Summary.Normalized.Emitted,
			Evidence: latest.Summary.EvidenceCount,
			Risks:    latest.Summary.RiskCount,
		},
		TopEvidence: topEvidence(evidenceResult.Evidence),
	})
}

func (s *Server) handleRisks(w http.ResponseWriter, r *http.Request) {
	latest, ok, err := s.latestRun()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_shadow_runs_failed", err.Error())
		return
	}
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
	if !ok || sensorMismatch(r.URL.Query().Get("sensor_id"), s.sensorID) {
		writeJSON(w, http.StatusOK, RiskListResponse{Items: []risk.Snapshot{}, Page: Page{Limit: limit, Total: 0}})
		return
	}
	batch, err := readRiskBatch(filepath.Join(latest.Dir, "risk-snapshots.json"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_risks_failed", err.Error())
		return
	}
	items, err := filterRisks(batch.Snapshots, r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_risk_query", err.Error())
		return
	}
	total := len(items)
	if cursor > total {
		cursor = total
	}
	end := cursor + limit
	if end > total {
		end = total
	}
	var next *string
	if end < total {
		value := strconv.Itoa(end)
		next = &value
	}
	writeJSON(w, http.StatusOK, RiskListResponse{Items: items[cursor:end], Page: Page{Limit: limit, NextCursor: next, Total: total}})
}

func (s *Server) handleIP(w http.ResponseWriter, r *http.Request, rest string) {
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/risk"):
		ip, err := pathIP(strings.TrimSuffix(rest, "/risk"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_ip", err.Error())
			return
		}
		s.handleIPRisk(w, ip)
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/evidence"):
		ip, err := pathIP(strings.TrimSuffix(rest, "/evidence"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_ip", err.Error())
			return
		}
		s.handleIPEvidence(w, ip)
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

func (s *Server) handleIPRisk(w http.ResponseWriter, ip string) {
	latest, ok, err := s.latestRun()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_shadow_runs_failed", err.Error())
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, normalRisk(ip))
		return
	}
	batch, err := readRiskBatch(filepath.Join(latest.Dir, "risk-snapshots.json"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_risks_failed", err.Error())
		return
	}
	for _, snapshot := range batch.Snapshots {
		if snapshot.IP == ip {
			writeJSON(w, http.StatusOK, snapshot)
			return
		}
	}
	writeJSON(w, http.StatusOK, normalRisk(ip))
}

func (s *Server) handleIPEvidence(w http.ResponseWriter, ip string) {
	latest, ok, err := s.latestRun()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_shadow_runs_failed", err.Error())
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"evidence": []evidence.Evidence{}})
		return
	}
	result, err := readEvidence(filepath.Join(latest.Dir, "evidence.json"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_evidence_failed", err.Error())
		return
	}
	items := make([]evidence.Evidence, 0)
	for _, item := range result.Evidence {
		if item.IP == ip {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt == items[j].CreatedAt {
			return items[i].EvidenceID < items[j].EvidenceID
		}
		return items[i].CreatedAt > items[j].CreatedAt
	})
	writeJSON(w, http.StatusOK, map[string]any{"evidence": items})
}

func (s *Server) handleIPEvents(w http.ResponseWriter, r *http.Request, ip string) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	latest, ok, err := s.latestRun()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_shadow_runs_failed", err.Error())
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"events": []normalized.Event{}})
		return
	}
	events, err := readNormalizedEvents(filepath.Join(latest.Dir, "normalized.jsonl"), ip, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_events_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleShadowRuns(w http.ResponseWriter) {
	runs, err := s.runs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_shadow_runs_failed", err.Error())
		return
	}
	items := make([]ShadowRun, 0, len(runs))
	for _, run := range runs {
		items = append(items, s.toShadowRun(run))
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": items})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	runs, err := s.runs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_shadow_runs_failed", err.Error())
		return
	}
	if len(runs) > limit {
		runs = runs[:limit]
	}
	logs := make([]AuditLog, 0, len(runs))
	for _, run := range runs {
		logs = append(logs, AuditLog{
			AuditID:   "audit-shadow-" + run.ID,
			Actor:     "system",
			Action:    "shadow.run",
			Target:    run.ID,
			Outcome:   fmt.Sprintf("risk_list_count=%d", run.Summary.RiskListCount),
			CreatedAt: run.Summary.FinishedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}

func (s *Server) latestRun() (runRecord, bool, error) {
	runs, err := s.runs()
	if err != nil {
		return runRecord{}, false, err
	}
	if len(runs) == 0 {
		return runRecord{}, false, nil
	}
	return runs[0], true, nil
}

func (s *Server) runs() ([]runRecord, error) {
	runsDir := filepath.Join(s.shadowDir, "runs")
	entries, err := os.ReadDir(runsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return []runRecord{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read runs directory: %w", err)
	}

	runs := make([]runRecord, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runDir := filepath.Join(runsDir, entry.Name())
		summary, err := readRunSummary(filepath.Join(runDir, "run-summary.json"))
		if err != nil {
			continue
		}
		started, _ := time.Parse(time.RFC3339Nano, summary.StartedAt)
		runs = append(runs, runRecord{ID: entry.Name(), Dir: runDir, Summary: summary, Started: started})
	}
	sort.Slice(runs, func(i, j int) bool {
		if !runs[i].Started.Equal(runs[j].Started) {
			return runs[i].Started.After(runs[j].Started)
		}
		return runs[i].ID > runs[j].ID
	})
	return runs, nil
}

func (s *Server) toShadowRun(run runRecord) ShadowRun {
	return ShadowRun{
		RunID:          run.ID,
		StartedAt:      run.Summary.StartedAt,
		FinishedAt:     run.Summary.FinishedAt,
		SensorID:       s.sensorID,
		PreviousOffset: run.Summary.PreviousOffset,
		NewOffset:      run.Summary.NewOffset,
		Truncated:      run.Summary.Truncated,
		Normalized:     normalizedCounts{Read: run.Summary.Normalized.Read, Emitted: run.Summary.Normalized.Emitted, Skipped: run.Summary.Normalized.Skipped, Malformed: run.Summary.Normalized.Malformed},
		EvidenceCount:  run.Summary.EvidenceCount,
		RiskCount:      run.Summary.RiskCount,
		RiskListCount:  run.Summary.RiskListCount,
	}
}

type normalizedCounts struct {
	Read      int `json:"read"`
	Emitted   int `json:"emitted"`
	Skipped   int `json:"skipped"`
	Malformed int `json:"malformed"`
}

func readRunSummary(path string) (shadow.RunSummary, error) {
	var summary shadow.RunSummary
	if err := readJSONFile(path, &summary); err != nil {
		return shadow.RunSummary{}, err
	}
	return summary, nil
}

func readRiskBatch(path string) (risk.BatchResult, error) {
	var batch risk.BatchResult
	if err := readJSONFile(path, &batch); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return risk.BatchResult{Snapshots: []risk.Snapshot{}}, nil
		}
		return risk.BatchResult{}, err
	}
	if batch.Snapshots == nil {
		batch.Snapshots = []risk.Snapshot{}
	}
	return batch, nil
}

func readEvidence(path string) (evidence.Result, error) {
	var result evidence.Result
	if err := readJSONFile(path, &result); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return evidence.Result{Evidence: []evidence.Evidence{}}, nil
		}
		return evidence.Result{}, err
	}
	if result.Evidence == nil {
		result.Evidence = []evidence.Evidence{}
	}
	return result, nil
}

func readJSONFile(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func filterRisks(snapshots []risk.Snapshot, query url.Values) ([]risk.Snapshot, error) {
	level := query.Get("level")
	if level != "" {
		if _, ok := levelRank(level); !ok {
			return nil, fmt.Errorf("unknown level: %s", level)
		}
	}
	q := strings.ToLower(query.Get("q"))
	from, err := optionalTime(query.Get("from"))
	if err != nil {
		return nil, fmt.Errorf("bad from: %w", err)
	}
	to, err := optionalTime(query.Get("to"))
	if err != nil {
		return nil, fmt.Errorf("bad to: %w", err)
	}

	items := make([]risk.Snapshot, 0, len(snapshots))
	for _, item := range snapshots {
		if level != "" && item.Level != level {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(item.IP), q) && !strings.Contains(strings.ToLower(item.Summary), q) {
			continue
		}
		updatedAt, ok := parseTime(item.UpdatedAt)
		if !from.IsZero() && (!ok || updatedAt.Before(from)) {
			continue
		}
		if !to.IsZero() && (!ok || updatedAt.After(to)) {
			continue
		}
		items = append(items, item)
	}
	sortRisks(items)
	return items, nil
}

func sortRisks(items []risk.Snapshot) {
	sort.Slice(items, func(i, j int) bool {
		leftRank, _ := levelRank(items[i].Level)
		rightRank, _ := levelRank(items[j].Level)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		return items[i].IP < items[j].IP
	})
}

func readNormalizedEvents(path string, ip string, limit int) ([]normalized.Event, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []normalized.Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	events := make([]normalized.Event, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var event normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if subjectIP, ok := event.Subject["ip"].(string); !ok || subjectIP != ip {
			continue
		}
		events = append(events, event)
		if len(events) > limit {
			events = events[len(events)-limit:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func topEvidence(items []evidence.Evidence) []EvidenceTypeStat {
	counts := map[string]int{}
	for _, item := range items {
		if item.Type != "" {
			counts[item.Type]++
		}
	}
	result := make([]EvidenceTypeStat, 0, len(counts))
	for evidenceType, count := range counts {
		result = append(result, EvidenceTypeStat{Type: evidenceType, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Type < result[j].Type
	})
	return result
}

func levelCounts(items []risk.Snapshot) LevelCounts {
	var counts LevelCounts
	for _, item := range items {
		switch item.Level {
		case "normal":
			counts.Normal++
		case "suspicious":
			counts.Suspicious++
		case "high":
			counts.High++
		case "confirmed":
			counts.Confirmed++
		}
	}
	return counts
}

func normalRisk(ip string) risk.Snapshot {
	return risk.Snapshot{
		IP:                ip,
		Score:             0,
		Level:             "normal",
		Confidence:        0,
		Window:            "none",
		EvidenceIDs:       []string{},
		Summary:           "未发现该 IP 的有效风险证据",
		RecommendedAction: "record",
		UpdatedAt:         time.Now().UTC().Format(time.RFC3339Nano),
	}
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

func sensorMismatch(querySensorID string, sensorID string) bool {
	return querySensorID != "" && querySensorID != sensorID
}

func pathIP(raw string) (string, error) {
	ip, err := url.PathUnescape(raw)
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", fmt.Errorf("ip is required")
	}
	return ip, nil
}

func optionalTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	value, ok := parseTime(raw)
	if !ok {
		return time.Time{}, fmt.Errorf("must be RFC3339")
	}
	return value, nil
}

func parseTime(raw string) (time.Time, bool) {
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return value, true
}

func levelRank(level string) (int, bool) {
	switch level {
	case "normal":
		return 0, true
	case "suspicious":
		return 1, true
	case "high":
		return 2, true
	case "confirmed":
		return 3, true
	default:
		return 0, false
	}
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
