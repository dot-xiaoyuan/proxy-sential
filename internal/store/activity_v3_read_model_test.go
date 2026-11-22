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

func TestActivityV3SummaryReadsOnlyRequiredFacts(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3", "true")
	t.Setenv("PROXY_SENTINEL_ACTIVITY_V3_CUTOVER", "")
	query := ActivityQuery{SensorID: "sensor-a", AsOf: "2026-09-28T06:07:00Z", SummaryOnly: true}
	summary, err := activityChartBucketSQL(query, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"activity_chart_facts_day_v3", " PREWHERE ", "toDateTime(", "'type','source_ip','domain'", "uniqExactIf("} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary lacks %s: %s", want, summary)
		}
	}
	if strings.Contains(summary, "ip_domain") || strings.Contains(summary, "tls_fp") || strings.Contains(summary, "normalized_events") {
		t.Fatalf("summary selected unrelated detail: %s", summary)
	}
	query.SummaryOnly = false
	detail, err := activityChartBucketSQL(query, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail, "activity_chart_facts_day_v3") || !strings.Contains(detail, "tls_fp") {
		t.Fatalf("detailed activity query changed: %s", detail)
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
	for _, required := range []string{"PREWHERE", "(f.bucket_start,f.sensor_id,f.campus_id,f.revision) IN(", "argMax(revision,published_at)", "max_execution_time=150", "max_threads=4"} {
		if !strings.Contains(query, required) {
			t.Fatalf("coarse materializer omitted %q: %s", required, query)
		}
	}
}

func TestActivityV3FiveMinuteDeltaSkipsUnchangedBuckets(t *testing.T) {
	query := activityV3FiveMinuteDeltaSQL(time.Date(2026, 11, 18, 5, 0, 0, 0, time.UTC), "sensor-a", "campus-a", "timestamp>=parseDateTime64BestEffort('2026-11-18T05:00:00Z',6)")
	for _, required := range []string{"EXCEPT", "event_count", "argMax(revision, published_at)", "activity_chart_facts_5m_v3", "AS changed"} {
		if !strings.Contains(query, required) {
			t.Fatalf("delta query omitted %q", required)
		}
	}
	if strings.Contains(query, "INSERT INTO activity_chart_facts_5m_v3") {
		t.Fatal("unchanged comparison must not insert a revision")
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

func TestActivityFiveMinuteScheduleDefersOpenBucket(t *testing.T) {
	bucket := time.Date(2026, 11, 18, 7, 0, 0, 0, time.UTC)
	closeAt := bucket.Add(5*time.Minute + activityBucketFinalizeDelay)
	cases := []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{"just opened", bucket, closeAt},
		{"one second before the gate", closeAt.Add(-time.Second), closeAt},
		{"at the gate", closeAt, closeAt.Add(activityBucketFinalizeDelay)},
		{"late receipt after close", closeAt.Add(10 * time.Minute), closeAt.Add(10*time.Minute + activityBucketFinalizeDelay)},
	}
	for _, c := range cases {
		if got := activityFiveMinuteSchedule(bucket, c.now); !got.Equal(c.want) {
			t.Fatalf("%s: not_before=%s want=%s", c.name, got, c.want)
		}
	}
	for _, c := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"open", bucket.Add(time.Minute), true},
		{"last instant open", closeAt.Add(-time.Nanosecond), true},
		{"closed at gate", closeAt, false},
		{"closed later", closeAt.Add(time.Hour), false},
	} {
		if got := activityFiveMinuteOpen(bucket, c.now); got != c.want {
			t.Fatalf("%s: open=%v want=%v", c.name, got, c.want)
		}
	}
}

func TestActivityCoarseGatePausesOnlyOnCurrentReading(t *testing.T) {
	cases := []struct {
		name         string
		lag          float64
		err          error
		sinceSuccess time.Duration
		wantPaused   bool
		wantReason   string
	}{
		{"no history yet and quiet", 3, nil, -1, false, ""},
		{"lag over the limit", activityCoarseMaxRealtimeLag.Seconds() + 1, nil, -1, true, "realtime lag above limit"},
		{"lag exactly at the limit", activityCoarseMaxRealtimeLag.Seconds(), nil, -1, false, ""},
		{"unavailable checkpoint", 0, errActivityTestCheckpoint, -1, true, "realtime checkpoint unavailable: checkpoint missing"},
		{"rate limited after success", 3, nil, 5 * time.Second, true, "claim rate limited"},
		{"spacing satisfied", 3, nil, activityCoarseClaimInterval, false, ""},
	}
	for _, c := range cases {
		paused, reason := activityCoarseGate(c.lag, c.err, c.sinceSuccess)
		if paused != c.wantPaused || reason != c.wantReason {
			t.Fatalf("%s: paused=%v reason=%q want paused=%v reason=%q", c.name, paused, reason, c.wantPaused, c.wantReason)
		}
	}
}

var errActivityTestCheckpoint = &activityTestError{"checkpoint missing"}

type activityTestError struct{ msg string }

func (e *activityTestError) Error() string { return e.msg }

func TestActivityCoarseSourceExpiredOnlyAppliesToRetainedFiveMinuteFacts(t *testing.T) {
	floor := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	expired := floor.Add(-time.Hour)
	inside := floor.Add(30 * time.Minute)
	if !activityCoarseSourceExpired(activityV3HourModel, expired, floor) {
		t.Fatal("hour before the retained floor must be treated as an unbuildable gap")
	}
	if activityCoarseSourceExpired(activityV3HourModel, inside, floor) {
		t.Fatal("hour inside the retained floor must stay buildable")
	}
	if activityCoarseSourceExpired(activityV3HourModel, expired, time.Time{}) {
		t.Fatal("an unknown floor must not cancel queued work")
	}
	for _, model := range []string{activityV3FiveMinuteModel, activityV3DayModel} {
		if activityCoarseSourceExpired(model, expired, floor) {
			t.Fatalf("%s does not read five-minute facts and must not be cancelled", model)
		}
	}
}

func TestActivityCoarseEffectiveLagSubtractsStructuralWindow(t *testing.T) {
	structural := activityFiveMinuteStructuralLag.Seconds()
	if got := activityCoarseEffectiveLag(structural); got != 0 {
		t.Fatalf("caught-up lane must report no backlog, got %.0fs", got)
	}
	if got := activityCoarseEffectiveLag(structural + 1); got != 1 {
		t.Fatalf("one second of real backlog must survive, got %.0fs", got)
	}
	if got := activityCoarseEffectiveLag(30); got != 0 {
		t.Fatalf("a fresh publish must not look like backlog, got %.0fs", got)
	}
	if got := activityCoarseEffectiveLag(structural + 300); got != 300 {
		t.Fatalf("five minutes of real backlog must be reported, got %.0fs", got)
	}
	// The gate must open with only the structural window, and pause once the real
	// backlog passes the limit.
	if paused, reason := activityCoarseGate(activityCoarseEffectiveLag(structural+30), nil, -1); paused {
		t.Fatalf("structural lag alone must not pause the rollups: %s", reason)
	}
	if paused, _ := activityCoarseGate(activityCoarseEffectiveLag(structural+activityCoarseMaxRealtimeLag.Seconds()+1), nil, -1); !paused {
		t.Fatal("real backlog beyond the limit must pause the rollups")
	}
}
