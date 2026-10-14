package controlplane

import (
	"errors"
	"net/http"
	"os"
	"proxy-sentinel/internal/store"
	"strconv"
	"strings"
)

func inventoryPathID(w http.ResponseWriter, rest string) (string, bool) {
	// Server routing already uses URL.Path (decoded once). Re-decoding would
	// corrupt legitimate percent signs inside an opaque session/endpoint ID.
	id := rest
	if strings.TrimSpace(id) == "" {
		writeError(w, 400, "bad_endpoint_id", "endpoint id is required")
		return "", false
	}
	return id, true
}
func (s *Server) handleInventorySnapshotEvidence(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.SplitN(strings.TrimSuffix(rest, "/evidence"), "/observations/", 2)
	if len(parts) != 2 {
		writeError(w, 400, "bad_evidence_path", "invalid evidence path")
		return
	}
	id, ok := inventoryPathID(w, parts[0])
	if !ok {
		return
	}
	record, ok := inventoryPathID(w, parts[1])
	if !ok {
		return
	}
	if strings.HasPrefix(record, "session:") {
		reader, ok := s.reader.(store.InventorySessionEvidenceReader)
		if !ok {
			writeError(w, 503, "session_evidence_unavailable", "会话证据入口不可用")
			return
		}
		ctx, cancel := contextWithRequestTimeout(r.Context())
		defer cancel()
		session, found, err := reader.GetInventorySessionEvidence(ctx, id, record)
		if err != nil {
			writeError(w, 400, "session_evidence_failed", "会话证据引用无效或读取失败")
			return
		}
		if !found {
			writeError(w, 404, "evidence_not_retained", "原始会话不在保留库中，关联事实仍留存")
			return
		}
		writeJSON(w, 200, session)
		return
	}
	reader, ok := s.reader.(store.InventorySnapshotEvidenceReader)
	if !ok {
		writeError(w, 503, "snapshot_evidence_unavailable", "快照证据入口不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	event, found, err := reader.GetInventorySnapshotEvidence(ctx, id, record)
	if err != nil {
		writeError(w, 500, "snapshot_evidence_failed", "读取快照证据失败")
		return
	}
	if !found {
		writeError(w, 404, "evidence_not_retained", "原始快照已不在保留库中，关联事实仍留存")
		return
	}
	writeJSON(w, 200, event)
}
func (s *Server) handleInventoryDetail(w http.ResponseWriter, r *http.Request, rest string) {
	id, ok := inventoryPathID(w, rest)
	if !ok {
		return
	}
	reader, ok := s.reader.(store.InventoryTraceReader)
	if !ok {
		writeError(w, 503, "inventory_projection_unavailable", "indexed inventory is unavailable")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	detail, found, err := reader.GetDeviceInventoryDetail(ctx, id)
	if err != nil {
		writeError(w, 500, "inventory_detail_failed", "读取终端摘要失败")
		return
	}
	if !found {
		writeError(w, 404, "endpoint_not_found", "endpoint not found")
		return
	}
	detail.Profile.DeviceNamesDisabled = os.Getenv("PROXY_SENTINEL_DEVICE_NAMES_DISABLED") == "true"
	writeJSON(w, 200, detail)
}
func (s *Server) handleInventoryObservations(w http.ResponseWriter, r *http.Request, rest string) {
	id, ok := inventoryPathID(w, rest)
	if !ok {
		return
	}
	p := r.URL.Query()
	q := store.EndpointObservationQuery{Kind: p.Get("kind"), Value: p.Get("value"), Source: p.Get("source"), Start: p.Get("start"), End: p.Get("end"), Cursor: p.Get("cursor")}
	if v := p.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n == 0 {
			writeError(w, 400, "bad_observation_query", "invalid limit")
			return
		}
		q.Limit = n
	}
	if err := store.ValidateEndpointObservationQuery(id, &q); err != nil {
		writeError(w, 400, "bad_observation_query", err.Error())
		return
	}
	reader, ok := s.reader.(store.InventoryTraceReader)
	if !ok {
		writeError(w, 503, "inventory_projection_unavailable", "indexed inventory is unavailable")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	page, err := reader.ListEndpointObservations(ctx, id, q)
	if errors.Is(err, store.ErrInventoryNotReady) {
		writeError(w, 503, "inventory_projection_not_ready", err.Error())
		return
	}
	if err != nil {
		writeError(w, 500, "observation_read_failed", "读取溯源明细失败")
		return
	}
	writeJSON(w, 200, page)
}
