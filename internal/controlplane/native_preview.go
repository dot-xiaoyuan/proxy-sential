package controlplane

import (
	"context"
	"net/http"
	"proxy-sentinel/internal/srunapi"
	"strings"
	"time"
)

// Preview is read-only confirmation material, never an execution authorization.
func (s *Server) handleNativeAccountPreview(w http.ResponseWriter, r *http.Request, id string) {
	s.operations.mu.Lock()
	connector, exists := s.operations.doc.Connectors[id]
	s.operations.mu.Unlock()
	if exists && connector.ConnectorType == "srun4k" && s.operations.db != nil {
		s.handleManagedAccountObservation(w, r, connector)
		return
	}
	runtime, configured := s.nativeActions[id]
	if !exists || !configured || runtime.Read == nil {
		writeError(w, 404, "native_connector_unavailable", "未配置该原生连接器")
		return
	}
	account := r.URL.Query().Get("account_id")
	if strings.TrimSpace(account) == "" || len(account) > 256 {
		writeError(w, 400, "invalid_account", "请提供明确账号")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	inventory, err := runtime.Read(ctx)
	if err != nil {
		writeError(w, 503, "native_inventory_unavailable", "完整在线清单不可用")
		return
	}
	plan, err := srunapi.PlanAccountDisconnect(inventory, account, runtime.CampusID, runtime.AccessDomain, time.Now().UTC(), 30*time.Second)
	if err != nil {
		writeError(w, 409, "native_plan_unavailable", "当前清单无法确认账号在线目标，请刷新身份数据")
		return
	}
	writeJSON(w, 200, map[string]any{"connector_id": id, "read_only": true, "coverage": "configured_source_only", "observed_at": inventory.ObservedAt, "plan": plan})
}
