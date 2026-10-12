package controlplane

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Context is permissioned separately from router identity. Only the persisted
// assessment provenance joins a profile; shared private IPs are not join keys.
func (s *Server) handleNetworkContext(w http.ResponseWriter, r *http.Request) {
	ids := strings.Split(r.URL.Query().Get("ids"), ",")
	if len(ids) > 100 {
		writeError(w, 400, "bad_ids", "设备数量过多")
		return
	}
	if s.operations == nil || s.operations.db == nil {
		writeError(w, 503, "context_storage", "设备档案存储不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	raw, _ := json.Marshal(ids)
	rows, err := s.operations.db.QueryContext(ctx, `SELECT source_assessment_id,list_item FROM shared_device_profiles WHERE merged_into_profile_id IS NULL AND source_assessment_id IN(SELECT jsonb_array_elements_text($1::jsonb)) ORDER BY profile_id`, string(raw))
	if err != nil {
		writeError(w, 500, "context_read", "读取设备档案失败")
		return
	}
	defer rows.Close()
	result := map[string][]json.RawMessage{}
	for rows.Next() {
		var id string
		var b json.RawMessage
		if err = rows.Scan(&id, &b); err != nil {
			writeError(w, 500, "context_read", "读取设备档案失败")
			return
		}
		result[id] = append(result[id], b)
	}
	if rows.Err() != nil {
		writeError(w, 500, "context_read", "读取设备档案失败")
		return
	}
	writeJSON(w, 200, result)
}
