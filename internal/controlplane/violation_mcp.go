package controlplane

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

type violationMCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	} `json:"params"`
}

func (s *Server) handleViolationMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method_not_allowed", "只支持只读 MCP 调用")
		return
	}
	var req violationMCPRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req) != nil || req.JSONRPC != "2.0" || req.Method == "" {
		writeError(w, 400, "invalid_mcp_request", "MCP 请求无效")
		return
	}
	result := any(nil)
	switch req.Method {
	case "initialize":
		result = map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "proxy-sentinel-violation-readonly", "version": "1"}}
	case "ping":
		result = map[string]any{}
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case "tools/list":
		result = map[string]any{"tools": []any{
			map[string]any{"name": "list_violation_cases", "description": "查询观察案件，不执行处置", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"account_id": map[string]string{"type": "string"}}}},
			map[string]any{"name": "get_violation_case", "description": "查询观察案件及拟提醒次数", "inputSchema": map[string]any{"type": "object", "required": []string{"case_id"}, "properties": map[string]any{"case_id": map[string]string{"type": "string"}}}},
			map[string]any{"name": "get_violation_timeline", "description": "查询案件的本地观察时间线", "inputSchema": map[string]any{"type": "object", "required": []string{"case_id"}, "properties": map[string]any{"case_id": map[string]string{"type": "string"}}}},
			map[string]any{"name": "list_violation_observations", "description": "查询拟提醒与拟处置观察记录", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"account_id": map[string]string{"type": "string"}}}},
		}}
	case "tools/call":
		path := ""
		switch req.Params.Name {
		case "list_violation_cases":
			path = "/violation-cases?limit=20&account_id=" + url.QueryEscape(req.Params.Arguments["account_id"])
		case "get_violation_case":
			id := req.Params.Arguments["case_id"]
			if id == "" || strings.ContainsAny(id, "/\\") {
				writeError(w, 400, "invalid_case_id", "案件编号无效")
				return
			}
			path = "/violation-cases/" + url.PathEscape(id)
		case "get_violation_timeline":
			id := req.Params.Arguments["case_id"]
			if id == "" || strings.ContainsAny(id, "/\\") {
				writeError(w, 400, "invalid_case_id", "案件编号无效")
				return
			}
			path = "/violation-cases/" + url.PathEscape(id) + "/timeline?limit=30"
		case "list_violation_observations":
			path = "/violation-observations?limit=20&account_id=" + url.QueryEscape(req.Params.Arguments["account_id"])
		default:
			writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32602, "message": "unknown read-only tool"}})
			return
		}
		// Reuse the authenticated read API without granting tools access to any
		// mutation route. The response carries the same error/data states.
		recorder := newMCPResponseRecorder()
		sub := r.Clone(r.Context())
		sub.Method = http.MethodGet
		sub.URL.Path = "/api/v1" + strings.SplitN(path, "?", 2)[0]
		if parts := strings.SplitN(path, "?", 2); len(parts) == 2 {
			sub.URL.RawQuery = parts[1]
		}
		s.handleViolationRead(recorder, sub, strings.TrimPrefix(sub.URL.Path, "/api/v1"))
		result = map[string]any{"content": []any{map[string]string{"type": "text", "text": recorder.body.String()}}, "isError": recorder.status >= 400}
	default:
		writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
		return
	}
	writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

type mcpResponseRecorder struct {
	header http.Header
	body   strings.Builder
	status int
}

func newMCPResponseRecorder() *mcpResponseRecorder {
	return &mcpResponseRecorder{header: make(http.Header), status: 200}
}
func (r *mcpResponseRecorder) Header() http.Header         { return r.header }
func (r *mcpResponseRecorder) WriteHeader(status int)      { r.status = status }
func (r *mcpResponseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
