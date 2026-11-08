package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"proxy-sentinel/internal/pagination"
	"proxy-sentinel/internal/store"
)

func auxiliaryPaginationRequest(w http.ResponseWriter, r *http.Request, maxLimit, defaultLimit int) (int, int, bool) {
	page, err := boundedInt(r.URL.Query().Get("page"), 1, 1, 1_000_000_000)
	if err != nil {
		writeError(w, 400, "bad_page", err.Error())
		return 0, 0, false
	}
	limit, err := boundedInt(r.URL.Query().Get("limit"), defaultLimit, 1, maxLimit)
	if err != nil {
		writeError(w, 400, "bad_limit", err.Error())
		return 0, 0, false
	}
	return page, limit, true
}

func writeAuxiliaryPagination(w http.ResponseWriter, value any, err error) {
	if errors.Is(err, pagination.ErrPageOutOfRange) {
		writeError(w, 400, "page_out_of_range", err.Error())
		return
	}
	if errors.Is(err, store.ErrInvalidStreamEventIndexQuery) || errors.Is(err, store.ErrStreamRiskCursor) {
		writeError(w, 400, "bad_pagination_query", err.Error())
		return
	}
	if err != nil {
		writeError(w, 503, "pagination_query_failed", "统计或页码定位暂不可用，请刷新后重试")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, value)
}

func (s *Server) handleAIRelayUsagePosition(w http.ResponseWriter, r *http.Request) {
	page, limit, ok := auxiliaryPaginationRequest(w, r, 50, 20)
	if !ok {
		return
	}
	v := r.URL.Query()
	now := time.Now().UTC()
	q := store.AIRelayUsageQuery{From: now.Add(-24 * time.Hour), To: now, IP: strings.TrimSpace(v.Get("ip")), Domain: strings.TrimSpace(v.Get("domain")), CampusID: strings.TrimSpace(v.Get("campus_id")), SensorID: strings.TrimSpace(v.Get("sensor_id")), Limit: limit}
	for key, target := range map[string]*time.Time{"from": &q.From, "to": &q.To} {
		if value := v.Get(key); value != "" {
			at, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				writeError(w, 400, "bad_time_range", "from and to must be RFC3339")
				return
			}
			*target = at
		}
	}
	if !q.From.Before(q.To) || q.To.After(now.Add(time.Minute)) || q.To.Sub(q.From) > 7*24*time.Hour || q.From.Before(now.Add(-7*24*time.Hour-time.Minute)) {
		writeError(w, 400, "bad_time_range", "range must be within retained 7 days")
		return
	}
	if err := store.ValidateAIRelayUsageQuery(q); err != nil {
		writeError(w, 400, "bad_relay_query", err.Error())
		return
	}
	reader, ok := s.reader.(interface {
		PositionAIRelayUsage(context.Context, store.AIRelayUsageQuery, int) (pagination.Position, error)
	})
	if !ok {
		writeError(w, 503, "ai_relay_unavailable", "AI relay query is unavailable")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	result, err := reader.PositionAIRelayUsage(ctx, q, page)
	writeAuxiliaryPagination(w, result, err)
}

func (s *Server) handleEndpointObservationPagination(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := inventoryPathID(w, id); !ok {
		return
	}
	page, limit, ok := auxiliaryPaginationRequest(w, r, 100, 20)
	if !ok {
		return
	}
	v := r.URL.Query()
	q := store.EndpointObservationQuery{Kind: v.Get("kind"), Value: v.Get("value"), Source: v.Get("source"), Start: v.Get("start"), End: v.Get("end"), AsOf: v.Get("as_of"), Limit: limit}
	if err := store.ValidateEndpointObservationQuery(id, &q); err != nil {
		writeError(w, 400, "bad_observation_query", err.Error())
		return
	}
	reader, ok := s.reader.(interface {
		EndpointObservationMetadata(context.Context, string, store.EndpointObservationQuery) (pagination.Metadata, error)
		PositionEndpointObservations(context.Context, string, store.EndpointObservationQuery, int) (pagination.Position, error)
	})
	if !ok {
		writeError(w, 503, "inventory_projection_unavailable", "indexed inventory is unavailable")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if strings.HasSuffix(r.URL.Path, "/metadata") {
		result, err := reader.EndpointObservationMetadata(ctx, id, q)
		writeAuxiliaryPagination(w, result, err)
		return
	}
	result, err := reader.PositionEndpointObservations(ctx, id, q, page)
	writeAuxiliaryPagination(w, result, err)
}

func (s *Server) handleStreamEventIndexPagination(w http.ResponseWriter, r *http.Request) {
	page, limit, ok := auxiliaryPaginationRequest(w, r, 100, 50)
	if !ok {
		return
	}
	v := r.URL.Query()
	from, fromErr := time.Parse(time.RFC3339Nano, v.Get("from"))
	to, toErr := time.Parse(time.RFC3339Nano, v.Get("to"))
	if fromErr != nil || toErr != nil {
		writeError(w, 400, "bad_stream_query", "valid from and to are required")
		return
	}
	q := store.StreamEventIndexQuery{ScopeID: v.Get("scope_id"), Protocol: v.Get("protocol"), From: from, To: to, Limit: limit}
	reader, ok := s.reader.(interface {
		StreamEventIndexMetadata(context.Context, store.StreamEventIndexQuery) (pagination.Metadata, error)
		PositionStreamEventIndex(context.Context, store.StreamEventIndexQuery, int) (pagination.Position, error)
	})
	if !ok {
		writeError(w, 503, "stream_index_unavailable", "stream event index is unavailable")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if strings.HasSuffix(r.URL.Path, "/metadata") {
		result, err := reader.StreamEventIndexMetadata(ctx, q)
		writeAuxiliaryPagination(w, result, err)
		return
	}
	result, err := reader.PositionStreamEventIndex(ctx, q, page)
	writeAuxiliaryPagination(w, result, err)
}

func (s *Server) handleIPTrafficObservationPagination(w http.ResponseWriter, r *http.Request, ip string) {
	page, limit, ok := auxiliaryPaginationRequest(w, r, 100, 20)
	if !ok {
		return
	}
	v := r.URL.Query()
	from, fromErr := time.Parse(time.RFC3339Nano, v.Get("from"))
	to, toErr := time.Parse(time.RFC3339Nano, v.Get("to"))
	owner := v.Get("source_owner")
	if owner == "" {
		owner = "handshake-sidecar"
	}
	q := store.IPTrafficObservationQuery{SensorID: s.sensorID, IP: ip, SourceOwner: owner, Protocol: v.Get("protocol"), From: from, To: to, Limit: limit}
	if fromErr != nil || toErr != nil || q.Validate() != nil || (v.Get("sensor_id") != "" && v.Get("sensor_id") != s.sensorID) {
		writeError(w, 400, "bad_traffic_query", "请选择本站采集器、有效来源和不超过 15 分钟的时间范围")
		return
	}
	reader, ok := s.reader.(interface {
		IPTrafficObservationMetadata(context.Context, store.IPTrafficObservationQuery) (pagination.Metadata, error)
		PositionIPTrafficObservations(context.Context, store.IPTrafficObservationQuery, int) (pagination.Position, error)
	})
	if !ok {
		writeError(w, 503, "traffic_observations_unavailable", "流量观察查询暂不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if strings.HasSuffix(r.URL.Path, "/metadata") {
		result, err := reader.IPTrafficObservationMetadata(ctx, q)
		writeAuxiliaryPagination(w, result, err)
		return
	}
	result, err := reader.PositionIPTrafficObservations(ctx, q, page)
	writeAuxiliaryPagination(w, result, err)
}

func (s *Server) handleStreamRiskCurrentPagination(w http.ResponseWriter, r *http.Request) {
	page, limit, ok := auxiliaryPaginationRequest(w, r, 100, 20)
	if !ok {
		return
	}
	v := r.URL.Query()
	kind := v.Get("subject_type")
	if kind == "" {
		kind = "ip"
	}
	level := v.Get("level")
	if kind != "ip" && kind != "account" {
		writeError(w, 400, "bad_subject_type", "subject_type must be ip or account")
		return
	}
	if level != "" && level != "normal" && level != "suspicious" && level != "high" && level != "confirmed" {
		writeError(w, 400, "bad_risk_level", "invalid risk level")
		return
	}
	reader, ok := s.reader.(interface {
		StreamRiskCurrentMetadata(context.Context, string, string, string) (pagination.Metadata, error)
		PositionStreamRiskCurrent(context.Context, string, string, string, int, int) (pagination.Position, error)
	})
	if !ok {
		writeError(w, 503, "stream_risk_unavailable", "scoped risk results are unavailable")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if strings.HasSuffix(r.URL.Path, "/metadata") {
		result, err := reader.StreamRiskCurrentMetadata(ctx, s.sensorID, kind, level)
		writeAuxiliaryPagination(w, result, err)
		return
	}
	result, err := reader.PositionStreamRiskCurrent(ctx, s.sensorID, kind, level, page, limit)
	writeAuxiliaryPagination(w, result, err)
}
