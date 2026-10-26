package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"proxy-sentinel/internal/store"
)

type ipTrafficObservationReader interface {
	ListIPTrafficObservations(context.Context, store.IPTrafficObservationQuery) (store.IPTrafficObservationPage, error)
}

func (s *Server) handleIPTrafficObservations(w http.ResponseWriter, r *http.Request, ip string) {
	values := r.URL.Query()
	from, fromErr := time.Parse(time.RFC3339Nano, values.Get("from"))
	to, toErr := time.Parse(time.RFC3339Nano, values.Get("to"))
	limit, limitErr := boundedInt(values.Get("limit"), 20, 1, 100)
	owner := values.Get("source_owner")
	if owner == "" {
		owner = "handshake-sidecar"
	}
	query := store.IPTrafficObservationQuery{SensorID: s.sensorID, IP: ip, SourceOwner: owner, Protocol: values.Get("protocol"), From: from, To: to, Limit: limit, Cursor: values.Get("cursor")}
	if fromErr != nil || toErr != nil || limitErr != nil || query.Validate() != nil || (values.Get("sensor_id") != "" && values.Get("sensor_id") != s.sensorID) {
		writeError(w, http.StatusBadRequest, "bad_traffic_query", "请选择本站采集器、有效来源和不超过 15 分钟的时间范围，每页最多 100 条")
		return
	}
	reader, ok := s.reader.(ipTrafficObservationReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "traffic_observations_unavailable", "流量观察查询暂不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	page, err := reader.ListIPTrafficObservations(ctx, query)
	if errors.Is(err, store.ErrInvalidStreamEventIndexQuery) {
		writeError(w, http.StatusBadRequest, "bad_traffic_cursor", "查询范围或来源已改变，请刷新后重试")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "traffic_observations_failed", "流量观察读取失败或超出查询预算，请缩小时间范围后重试")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, page)
}
