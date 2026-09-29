package appdomain

import (
	"context"
	"proxy-sentinel/internal/normalized"
	"sort"
	"testing"
	"time"
)

type memorySource struct{ events []normalized.Event }

func (m *memorySource) ScanApplicationEvents(ctx context.Context, q Scan) ([]normalized.Event, error) {
	out := []normalized.Event{}
	for _, e := range m.events {
		tm, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
		if tm.Before(q.From) || !tm.Before(q.To) || q.After.Timestamp != "" && !CursorLess(q.After, EventCursor(e)) {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return CursorLess(EventCursor(out[i]), EventCursor(out[j])) })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func TestServicePersistenceVersionAndLateArrival(t *testing.T) {
	now := time.Now().UTC()
	e := fixtureEvent("1", "tls", "a.weixin.qq.com", "c", float64(12))
	e.Timestamp = now.Add(-time.Hour).Format(time.RFC3339Nano)
	src := &memorySource{[]normalized.Event{e}}
	dir := t.TempDir()
	s, err := OpenService(dir, src)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ChangeLibrary(testBundle(t, "v1"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err = s.ChangeLibrary(testBundle(t, "v2"), ""); err != nil {
		t.Fatal(err)
	}
	// A subsequent scan must not silently reclassify existing observations.
	if _, err = s.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot()[0].BundleVersion != "v1" {
		t.Fatal("silently reclassified")
	}
	s, err = OpenService(dir, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Snapshot()) != 1 {
		t.Fatal("persistence missing")
	}
	if err = s.StartReclassification(now); err != nil {
		t.Fatal(err)
	}
	if err = s.ChangeLibrary(testBundle(t, "v3"), ""); err == nil {
		t.Fatal("changed pinned library")
	}
	if _, err = s.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	// Restart after a committed page resumes its persisted cursor.
	s, err = OpenService(dir, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if s.Status().Job.Status != "completed" || s.Snapshot()[0].BundleVersion != "v2" {
		t.Fatal(s.Status())
	}
	late := e
	late.EventID = "late"
	late.Timestamp = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	src.events = append(src.events, late)
	for i := 0; i < 4; i++ {
		if _, err = s.Step(context.Background(), now); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.Snapshot()) != 2 {
		t.Fatal("late arrival lost")
	}
}
func TestUnknownExportPrivacyAndIdempotence(t *testing.T) {
	o := Observe(fixtureEvent("1", "dns", "unknown.example.com", "", nil), nil)
	q := Query{From: time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)}
	rows := UnknownDomains([]Observation{o, o}, q)
	if len(rows) != 1 || rows[0].ObservationCount != 1 {
		t.Fatal(rows)
	}
}

func TestJobPauseResumeCancelPreservesCommittedCursor(t *testing.T) {
	now := time.Now().UTC()
	e := fixtureEvent("control", "tls", "a.weixin.qq.com", "c", float64(12))
	e.Timestamp = now.Add(-time.Hour).Format(time.RFC3339Nano)
	dir := t.TempDir()
	src := &memorySource{[]normalized.Event{e}}
	s, err := OpenService(dir, src)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ChangeLibrary(testBundle(t, "control-v1"), ""); err != nil {
		t.Fatal(err)
	}
	if err = s.StartReclassification(now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	before := s.Status().Job
	if err = s.ControlJob("pause"); err != nil {
		t.Fatal(err)
	}
	if err = s.ChangeLibrary(testBundle(t, "other"), ""); err == nil {
		t.Fatal("paused job lost pinned library")
	}
	s, err = OpenService(dir, src)
	if err != nil {
		t.Fatal(err)
	}
	if s.Status().Job.Status != "paused" || s.Status().Job.After != before.After {
		t.Fatal(s.Status())
	}
	if err = s.ControlJob("resume"); err != nil {
		t.Fatal(err)
	}
	if err = s.ControlJob("cancel"); err != nil {
		t.Fatal(err)
	}
	if s.Status().Job.After != before.After || len(s.Snapshot()) != 1 {
		t.Fatal("cancel discarded committed work")
	}
	if err = s.ControlJob("resume"); err == nil {
		t.Fatal("cancelled job resumed")
	}
}
