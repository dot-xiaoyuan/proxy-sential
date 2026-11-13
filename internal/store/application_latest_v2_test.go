package store

import (
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/appdomain"
)

func TestApplicationCompactLatestReaderUsesStructuredIndex(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_APPLICATION_LATEST_V2_READ", "true")
	q := appdomain.Query{From: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC), SensorID: "campus-204"}
	for _, query := range []string{appLatestWindow(q, "target_id"), applicationObservationFactsSQL(q, false), applicationObservationFactsSQL(q, true)} {
		if !strings.Contains(query, "application_latest_observations_v2 FINAL") || strings.Contains(query, "application_latest_observations FINAL") {
			t.Fatalf("compact latest flag did not move every query path: %s", query)
		}
	}
}
