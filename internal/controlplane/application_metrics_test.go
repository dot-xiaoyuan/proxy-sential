package controlplane

import (
	"bytes"
	"proxy-sentinel/internal/appdomain"
	"strings"
	"testing"
)

func TestApplicationProcessingMetricsDistinguishUnknownCursor(t *testing.T) {
	var out bytes.Buffer
	writeApplicationMetrics(&out, appdomain.ProcessingStatus{Realtime: appdomain.Job{Error: "database down", Retries: 2}, History: appdomain.Job{RequestedControl: "pause", Processed: 1000}})
	if strings.Contains(out.String(), "cursor_age_seconds") {
		t.Fatal("missing cursor incorrectly exported as zero lag")
	}
	for _, want := range []string{`proxy_sentinel_application_job_failed{lane="realtime"} 1`, `proxy_sentinel_application_control_pending{lane="history"} 1`, `proxy_sentinel_application_job_retries{lane="realtime"} 2`} {
		if !strings.Contains(out.String(), want) {
			t.Fatal(out.String())
		}
	}
}
