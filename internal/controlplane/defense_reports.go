package controlplane

import (
	"context"
	"net/http"
	"time"

	"proxy-sentinel/internal/store"
)

type routerObservationReportReader interface {
	GetRouterObservationReport(context.Context) (store.RouterObservationReport, error)
}

func (s *Server) handleRouterObservationReport(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(routerObservationReportReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "router_report_unavailable", "路由器统计不可用")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	report, err := reader.GetRouterObservationReport(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "router_report_unavailable", "路由器统计读取失败")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type sharedBehaviorReportReader interface {
	GetSharedBehaviorReport(context.Context) (store.SharedBehaviorReport, error)
}

func (s *Server) handleSharedBehaviorReport(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(sharedBehaviorReportReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "shared_behavior_report_unavailable", "共享观测统计不可用")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	report, err := reader.GetSharedBehaviorReport(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "shared_behavior_report_unavailable", "共享观测统计读取失败")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

type sharedDecisionTrendBucket struct {
	From         time.Time `json:"from"`
	Matched      int64     `json:"matched"`
	Insufficient int64     `json:"insufficient"`
	Expired      int64     `json:"expired"`
}

type sharedDecisionTrend struct {
	From          time.Time                   `json:"from"`
	To            time.Time                   `json:"to"`
	BucketMinutes int                         `json:"bucket_minutes"`
	Buckets       []sharedDecisionTrendBucket `json:"buckets"`
}

func (s *Server) handleSharedDecisionTrend(w http.ResponseWriter, r *http.Request) {
	window, interval, minutes := time.Hour, 5*time.Minute, "5 minutes"
	switch r.URL.Query().Get("window") {
	case "", "1h":
	case "15m":
		window, interval, minutes = 15*time.Minute, time.Minute, "1 minute"
	default:
		writeError(w, http.StatusBadRequest, "bad_window", "查询窗口仅支持 15m 或 1h")
		return
	}
	if s.productPolicies == nil || s.productPolicies.db == nil {
		writeError(w, http.StatusServiceUnavailable, "shared_trend_unavailable", "共享判定统计不可用")
		return
	}
	to := time.Now().UTC().Truncate(interval)
	from := to.Add(-window)
	result := sharedDecisionTrend{
		From: from, To: to, BucketMinutes: int(interval / time.Minute),
		Buckets: make([]sharedDecisionTrendBucket, int(window/interval)),
	}
	for i := range result.Buckets {
		result.Buckets[i].From = from.Add(time.Duration(i) * interval)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	// Use the shared result/time index across one fixed, bounded window.
	// No policy documents or account identifiers are needed for the report.
	rows, err := s.productPolicies.db.QueryContext(ctx, `SELECT date_bin($3::interval,evaluated_at,$1::timestamptz),
 count(*) FILTER(WHERE result='matched'), count(*) FILTER(WHERE result='insufficient'), count(*) FILTER(WHERE result='expired')
 FROM policy_decision_records
 WHERE trigger_type='shared_access' AND result IN ('matched','insufficient','expired')
 AND evaluated_at >= $1 AND evaluated_at < $2 GROUP BY 1`, from, to, minutes)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "shared_trend_unavailable", "共享判定统计读取失败")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var bucket sharedDecisionTrendBucket
		if err := rows.Scan(&bucket.From, &bucket.Matched, &bucket.Insufficient, &bucket.Expired); err != nil {
			writeError(w, http.StatusServiceUnavailable, "shared_trend_unavailable", "共享判定统计读取失败")
			return
		}
		i := int(bucket.From.Sub(from) / interval)
		result.Buckets[i] = bucket
	}
	if rows.Err() != nil {
		writeError(w, http.StatusServiceUnavailable, "shared_trend_unavailable", "共享判定统计读取失败")
		return
	}
	writeJSON(w, http.StatusOK, result)
}
