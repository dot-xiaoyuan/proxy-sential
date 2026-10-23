package controlplane

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
)

func (s *Server) handleViolationReleasePreview(w http.ResponseWriter, r *http.Request, path string) {
	if s.operations == nil || s.operations.db == nil {
		writeError(w, 503, "violation_store_unavailable", "观察数据暂不可用")
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, "/violation-cases/"), "/release-preview")
	if id == "" || strings.Contains(id, "/") || len(id) > 300 {
		writeError(w, 400, "bad_case_id", "案件编号无效")
		return
	}
	var input struct {
		Reason string `json:"reason"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&input) != nil || strings.TrimSpace(input.Reason) == "" {
		writeError(w, 400, "bad_reason", "需填写复核原因")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 100 {
		writeError(w, 400, "idempotency_required", "需提供幂等键")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	var account string
	err := s.operations.db.QueryRowContext(ctx, `SELECT account_id FROM violation_cases WHERE case_id=$1`, id).Scan(&account)
	if err == sql.ErrNoRows {
		writeError(w, 404, "case_not_found", "案件不存在")
		return
	}
	if err != nil {
		writeError(w, 503, "violation_query_failed", "案件查询失败")
		return
	}
	facts, _ := json.Marshal(map[string]string{"case_id": id, "reason": strings.TrimSpace(input.Reason), "actor": sessionFromContext(r.Context()).User.ID, "execution": "observation_only"})
	observationKey := "release-preview:" + id + ":" + key
	_, err = s.operations.db.ExecContext(ctx, `INSERT INTO violation_observations(observation_key,kind,target,case_id,facts) VALUES($1,'拟人工解封',$2,$3,$4)
		ON CONFLICT(observation_key) DO NOTHING`, observationKey, account,id, facts)
	if err != nil {
		writeError(w, 503, "observation_save_failed", "观察记录保存失败")
		return
	}
	writeJSON(w, 200, map[string]any{"observation_key": observationKey, "status": "拟人工解封", "external_request_sent": false})
}
