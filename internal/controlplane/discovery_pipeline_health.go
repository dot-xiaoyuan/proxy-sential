package controlplane

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"proxy-sentinel/internal/discovery"
)

func (s *Server) discoveryPipelineStatus(ctx context.Context) (discovery.PipelineStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	return (discovery.Repository{DB: s.operations.db}).PipelineStatus(ctx)
}
func (s *Server) discoveryPipelineHealth(ctx context.Context) componentHealth {
	status, err := s.discoveryPipelineStatus(ctx)
	if err != nil {
		return componentHealth{Status: "unavailable", Error: "discovery_pipeline_read_failed"}
	}
	return componentHealth{Status: status.Status}
}
func (s *Server) discoveryPipelineMetrics(ctx context.Context, w io.Writer) {
	if s.operations == nil || s.operations.db == nil {
		return
	}
	status, err := s.discoveryPipelineStatus(ctx)
	available := 1
	if err != nil {
		available = 0
	}
	fmt.Fprintf(w, "# TYPE proxy_sentinel_discovery_available gauge\nproxy_sentinel_discovery_available %d\n", available)
	if err != nil {
		return
	}
	writeDiscoveryPipelineMetrics(w, status)
}
func writeDiscoveryPipelineMetrics(w io.Writer, status discovery.PipelineStatus) {
	unhealthy := 0
	for _, consumer := range status.Consumers {
		if consumer.State != "running" {
			unhealthy++
		}
	}
	fmt.Fprintf(w, "proxy_sentinel_discovery_consumer_unhealthy{role=\"dhcp\"} %d\n", unhealthy)

	for _, lane := range status.Lanes {
		label := "lane=" + strconv.Quote(lane.Lane)
		fmt.Fprintf(w, "proxy_sentinel_discovery_events_per_second{%s} %g\n", label, lane.EventsPerSecond)
		for _, v := range []struct {
			name  string
			value int64
		}{{"pending_batches", lane.PendingBatches}, {"remaining_events", lane.RemainingEvents}, {"historical_failed_batches", lane.FailedBatches}, {"processed_events", lane.ProcessedEvents}, {"retries", lane.Retries}, {"completed_segments", lane.CompletedSegments}, {"timeout_failures", lane.TimeoutFailures}} {
			fmt.Fprintf(w, "proxy_sentinel_discovery_%s{%s} %d\n", v.name, label, v.value)
		}
		for _, v := range []struct {
			name string
			at   *time.Time
		}{{"heartbeat", lane.HeartbeatAt}, {"progress", lane.LastProgressAt}, {"oldest_pending", lane.OldestPendingAt}} {
			if v.at != nil {
				fmt.Fprintf(w, "proxy_sentinel_discovery_%s_timestamp_seconds{%s} %d\n", v.name, label, v.at.Unix())
			}
		}
		fmt.Fprintf(w, "proxy_sentinel_discovery_state{%s,state=%s} 1\n", label, strconv.Quote(lane.State))
		for stage, v := range lane.Stages {
			l := label + ",stage=" + strconv.Quote(stage)
			fmt.Fprintf(w, "proxy_sentinel_discovery_stage_calls{%s} %d\nproxy_sentinel_discovery_stage_errors{%s} %d\nproxy_sentinel_discovery_stage_seconds_sum{%s} %g\nproxy_sentinel_discovery_stage_seconds_max{%s} %g\n", l, v.Calls, l, v.Errors, l, v.Seconds, l, v.MaxSeconds)
		}
	}
}
