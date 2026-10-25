package controlplane

import (
	"bytes"
	"proxy-sentinel/internal/discovery"
	"strings"
	"testing"
)

func TestDiscoveryMetricsContainNoEventLabels(t *testing.T) {
	var b bytes.Buffer
	writeDiscoveryPipelineMetrics(&b, discovery.PipelineStatus{Status: "delayed", Lanes: []discovery.PipelineLane{{Lane: "realtime", PendingBatches: 10, RemainingEvents: 499, State: "stalled", Stages: map[string]discovery.StageStats{"commit": {Calls: 3, Errors: 1}}}}})
	text := b.String()
	for _, fragment := range []string{`pending_batches{lane="realtime"} 10`, `remaining_events{lane="realtime"} 499`, `state{lane="realtime",state="stalled"} 1`, `stage_errors{lane="realtime",stage="commit"} 1`} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("missing %s in %s", fragment, text)
		}
	}
	if strings.Contains(text, "event_id") || strings.Contains(text, "batch_id") {
		t.Fatal("unbounded metric labels")
	}
}
