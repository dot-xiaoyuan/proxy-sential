package store

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeActivityWindowSupportsThirtyDays(t *testing.T) {
	name, duration, err := NormalizeActivityWindow("30d")
	if err != nil || name != "30d" || duration != 30*24*time.Hour {
		t.Fatalf("unexpected window: name=%q duration=%s err=%v", name, duration, err)
	}
}

func TestParseReadModelTimeAcceptsPostgresAndRFC3339(t *testing.T) {
	want := time.Date(2026, 9, 28, 6, 44, 40, 830122000, time.UTC)
	for _, raw := range []string{
		"2026-09-28 06:44:40.830122+00",
		"2026-09-28T06:44:40.830122Z",
		"2026-09-28T14:44:40.830122+08:00",
	} {
		got, err := parseReadModelTime(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if !got.Equal(want) {
			t.Fatalf("parse %q=%s, want %s", raw, got, want)
		}
	}
}

func TestActivityV3ThirtyDayQueryUsesPublishedHierarchy(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3", "true")
	t.Setenv("PROXY_SENTINEL_ACTIVITY_V3_CUTOVER", "2026-09-01T00:00:00Z")
	query, err := activityChartFactRowsSQL(ActivityQuery{SensorID: "sensor-a", AsOf: "2026-09-28T06:07:00Z"}, 30*24*time.Hour, []string{"type"})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"activity_chart_facts_5m_v3", "activity_chart_facts_hour_v3", "activity_chart_facts_day_v3", "activity_chart_bucket_versions_v3", "argMax(revision,published_at)"} {
		if !strings.Contains(query, required) {
			t.Fatalf("query omitted %s: %s", required, query)
		}
	}
	if strings.Contains(query, "activity_chart_facts_day_v3 FINAL") {
		t.Fatal("v3 hot query must not use FINAL")
	}
	if strings.Contains(query, "INNER JOIN") || !strings.Contains(query, "(f.bucket_start,f.sensor_id,f.campus_id,f.revision) IN(") {
		t.Fatalf("v3 hot query must prune superseded revisions with a primary-key tuple IN: %s", query)
	}
	if strings.Contains(query, "normalized_event_features") || strings.Contains(query, "normalized_events") {
		t.Fatalf("v3 interactive query must not fall back to raw events: %s", query)
	}
}

func TestActivityV3CoarseMaterializerPrunesSupersededRevisions(t *testing.T) {
	query, granularity, _, err := activityV3CoarseMaterializeSQL(readModelJob{
		Model:       activityV3HourModel,
		BucketStart: time.Date(2026, 9, 28, 6, 0, 0, 0, time.UTC),
		SensorID:    "sensor-a",
		CampusID:    "campus-a",
	}, 42)
	if err != nil {
		t.Fatal(err)
	}
	if granularity != "hour" {
		t.Fatalf("unexpected granularity %q", granularity)
	}
	if strings.Contains(query, " JOIN") || strings.Contains(query, " FINAL") {
		t.Fatalf("coarse materializer must not scan superseded revisions: %s", query)
	}
	for _, required := range []string{"PREWHERE", "(f.bucket_start,f.sensor_id,f.campus_id,f.revision) IN(", "argMax(revision,published_at)", "max_execution_time=30"} {
		if !strings.Contains(query, required) {
			t.Fatalf("coarse materializer omitted %q: %s", required, query)
		}
	}
}

func TestActivityParentNotBeforeDebouncesLateChildren(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	if got, want := activityParentNotBefore(now.Add(-time.Hour), now, 90*time.Second), now.Add(90*time.Second); !got.Equal(want) {
		t.Fatalf("late parent not_before=%s want=%s", got, want)
	}
	if got, want := activityParentNotBefore(now.Add(time.Hour), now, 90*time.Second), now.Add(time.Hour); !got.Equal(want) {
		t.Fatalf("future parent not_before=%s want=%s", got, want)
	}
}

func TestActivitySuccessfulNotBeforeRateLimitsCoarseRebuilds(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		model string
		want  time.Time
	}{
		{activityV3FiveMinuteModel, now.Add(30 * time.Second)},
		{activityV3HourModel, now.Add(10 * time.Minute)},
		{activityV3DayModel, now.Add(30 * time.Minute)},
		{"other", now},
	}
	for _, test := range tests {
		if got := activitySuccessfulNotBefore(test.model, now); !got.Equal(test.want) {
			t.Fatalf("model %s not_before=%s want=%s", test.model, got, test.want)
		}
	}
}
