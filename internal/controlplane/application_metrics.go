package controlplane

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"proxy-sentinel/internal/appdomain"
)

func (s *Server) applicationMetrics(ctx context.Context, w io.Writer) {
	if s.applications == nil {
		return
	}
	state, err := s.applications.Processing(ctx)
	available := 1
	if err != nil {
		available = 0
	}
	fmt.Fprintf(w, "# HELP proxy_sentinel_application_processing_available Whether application task status can be read.\n# TYPE proxy_sentinel_application_processing_available gauge\nproxy_sentinel_application_processing_available %d\n", available)
	if err != nil {
		return
	}
	writeApplicationMetrics(w, state)
}
func writeApplicationMetrics(w io.Writer, state appdomain.ProcessingStatus) {
	fmt.Fprintf(w, "# TYPE proxy_sentinel_application_query_milliseconds gauge\nproxy_sentinel_application_query_milliseconds %d\n", state.QueryMillis)
	for _, lane := range []struct {
		name string
		job  appdomain.Job
	}{{"realtime", state.Realtime}, {"history", state.History}, {"reconcile", state.Reconcile}} {
		labels := "lane=" + strconv.Quote(lane.name)
		fmt.Fprintf(w, "proxy_sentinel_application_job_processed{%s} %d\nproxy_sentinel_application_batch_milliseconds{%s} %d\nproxy_sentinel_application_job_retries{%s} %d\n", labels, lane.job.Processed, labels, lane.job.BatchMillis, labels, lane.job.Retries)
		failed := 0
		if lane.job.Error != "" {
			failed = 1
		}
		pending := 0
		if lane.job.RequestedControl != "" {
			pending = 1
		}
		fmt.Fprintf(w, "proxy_sentinel_application_job_failed{%s} %d\nproxy_sentinel_application_control_pending{%s} %d\n", labels, failed, labels, pending)
		if cursorTime, err := time.Parse(time.RFC3339Nano, lane.job.After.Timestamp); err == nil {
			fmt.Fprintf(w, "proxy_sentinel_application_cursor_age_seconds{%s} %g\n", labels, max(0, time.Since(cursorTime).Seconds()))
		}
		if ts, err := time.Parse(time.RFC3339Nano, lane.job.LastSuccess); err == nil {
			fmt.Fprintf(w, "proxy_sentinel_application_last_success_timestamp_seconds{%s} %d\n", labels, ts.Unix())
		}
	}
}
