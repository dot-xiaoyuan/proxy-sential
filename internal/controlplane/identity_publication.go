package controlplane

import (
	"database/sql"
	"net/http"
	"proxy-sentinel/internal/store"
)

func (s *Server) handleIdentityPublication(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeIdentityBridge(w, r) {
		return
	}
	q := r.URL.Query()
	scope := store.IdentityScope{Source: q.Get("source"), SensorID: q.Get("sensor_id"), CampusID: q.Get("campus_id"), AccessDomain: q.Get("access_domain")}
	var id, state string
	err := s.operations.db.QueryRowContext(r.Context(), `SELECT snapshot_id,calibration_state FROM identity_pipeline_scopes WHERE scope_key=$1`, store.IdentityScopeKey(scope)).Scan(&id, &state)
	if err != nil && err != sql.ErrNoRows {
		writeError(w, 503, "identity_publication_unavailable", "calibration status unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"snapshot_id": q.Get("snapshot_id"), "published": id == q.Get("snapshot_id") && id != "" && state == "completed", "calibration_state": state})
}
