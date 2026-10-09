package controlplane

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"proxy-sentinel/internal/store"
)

func (s *Server) handleRouterObservations(w http.ResponseWriter, r *http.Request, path string) {
	reader, ok := s.reader.(store.RouterObservationReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "router_observations_unavailable", "路由观察存储不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if path != "/router-observations" {
		id, err := url.PathUnescape(strings.TrimPrefix(path, "/router-observations/"))
		if err != nil || strings.TrimSpace(id) == "" || strings.Contains(id, "/") {
			writeError(w, http.StatusBadRequest, "bad_router_observation_id", "路由观察标识无效")
			return
		}
		item, found, err := reader.GetRouterObservation(ctx, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "read_router_observation_failed", err.Error())
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "router_observation_not_found", "路由观察不存在")
			return
		}
		writeJSON(w, http.StatusOK, item)
		return
	}
	query, err := routerObservationQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_router_observation_query", err.Error())
		return
	}
	page, err := reader.ListRouterObservations(ctx, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_router_observations_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func routerObservationQuery(values url.Values) (store.RouterQuery, error) {
	limit, err := boundedInt(values.Get("limit"), 20, 1, 100)
	if err != nil {
		return store.RouterQuery{}, err
	}
	cursor, err := cursorOffset(values.Get("cursor"))
	if err != nil {
		return store.RouterQuery{}, err
	}
	parseConfidence := func(name string) (*int, error) {
		raw := strings.TrimSpace(values.Get(name))
		if raw == "" {
			return nil, nil
		}
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value < 0 || value > 100 {
			return nil, &routerQueryError{message: name + " 必须是 0 到 100 的整数"}
		}
		return &value, nil
	}
	minimum, err := parseConfidence("confidence_min")
	if err != nil {
		return store.RouterQuery{}, err
	}
	maximum, err := parseConfidence("confidence_max")
	if err != nil {
		return store.RouterQuery{}, err
	}
	if minimum != nil && maximum != nil && *minimum > *maximum {
		return store.RouterQuery{}, &routerQueryError{message: "confidence_min 不能大于 confidence_max"}
	}
	var infrastructure *bool
	if raw := strings.TrimSpace(values.Get("infrastructure")); raw != "" {
		value, parseErr := strconv.ParseBool(raw)
		if parseErr != nil {
			return store.RouterQuery{}, &routerQueryError{message: "infrastructure 必须是 true 或 false"}
		}
		infrastructure = &value
	}
	var hasAuthBinding *bool
	if raw := strings.TrimSpace(values.Get("has_auth_binding")); raw != "" {
		value, parseErr := strconv.ParseBool(raw)
		if parseErr != nil {
			return store.RouterQuery{}, &routerQueryError{message: "has_auth_binding 必须是 true 或 false"}
		}
		hasAuthBinding = &value
	}
	includeCandidates := false
	if raw := strings.TrimSpace(values.Get("include_candidates")); raw != "" {
		includeCandidates, err = strconv.ParseBool(raw)
		if err != nil {
			return store.RouterQuery{}, &routerQueryError{message: "include_candidates 必须是 true 或 false"}
		}
	}
	status := strings.TrimSpace(values.Get("status"))
	if status != "" && status != "candidate" && status != "likely" && status != "confirmed" {
		return store.RouterQuery{}, &routerQueryError{message: "status 无效"}
	}
	role := strings.TrimSpace(values.Get("role"))
	if role == "" {
		role = "router"
	}
	if role != "router" && role != "ap" && role != "switch" && role != "firewall" && role != "endpoint" && role != "unknown" {
		return store.RouterQuery{}, &routerQueryError{message: "role 无效"}
	}
	return store.RouterQuery{
		Keyword: strings.TrimSpace(values.Get("keyword")), IP: strings.TrimSpace(values.Get("ip")), MAC: strings.TrimSpace(values.Get("mac")), VLAN: strings.TrimSpace(values.Get("vlan")), Brand: strings.TrimSpace(values.Get("brand")), Model: strings.TrimSpace(values.Get("model")), Role: role, Status: status, IncludeCandidates: includeCandidates, Source: strings.TrimSpace(values.Get("source")), ConfidenceMin: minimum, ConfidenceMax: maximum, FirstSeenFrom: strings.TrimSpace(values.Get("first_seen_from")), FirstSeenTo: strings.TrimSpace(values.Get("first_seen_to")), LastSeenFrom: strings.TrimSpace(values.Get("last_seen_from")), LastSeenTo: strings.TrimSpace(values.Get("last_seen_to")), Infrastructure: infrastructure, HasAuthBinding: hasAuthBinding, Limit: limit, Cursor: cursor,
	}, nil
}

type routerQueryError struct{ message string }

func (e *routerQueryError) Error() string { return e.message }
