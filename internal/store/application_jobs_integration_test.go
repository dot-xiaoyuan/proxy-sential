package store

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/appdomain"
)

type appTransport func(*http.Request) (*http.Response, error)

func (f appTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestApplicationDatabaseBatchRecoveryAndControl(t *testing.T) {
	d := appIntegrationDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sensor := fmt.Sprintf("app-jobs-%d", now.UnixNano())
	var existing int
	if err := d.store.pg.db.QueryRowContext(ctx, "SELECT count(*) FROM application_processing_jobs").Scan(&existing); err != nil {
		t.Fatal(err)
	}
	if existing != 0 {
		t.Fatal("use an isolated application test database; task rows already exist")
	}
	t.Cleanup(func() {
		_, _ = d.store.pg.db.ExecContext(ctx, "DELETE FROM application_processing_batches")
		_, _ = d.store.pg.db.ExecContext(ctx, "DELETE FROM application_processing_jobs")
		_ = d.store.ch.exec(ctx, "ALTER TABLE normalized_events DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=2")
		cleanupApplicationTestData(ctx, d.store, sensor, false)
	})
	sql := fmt.Sprintf(`INSERT INTO normalized_events(timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,observer_json,payload_json,flow_json,raw_ref_json) SELECT now64(6)-INTERVAL 1 HOUR,concat('app-job-',toString(number)),'v1','test','tls','tls',%s,'10.0.0.1','{}','{"sni":"weixin.qq.com"}',concat('{"connection_id":"c',toString(number),'","bytes_toserver":10}'),'{}' FROM numbers(3)`, chQuote(sensor))
	if err := d.store.ch.exec(ctx, sql); err != nil {
		t.Fatal(err)
	}
	raw, err := appdomain.ExampleBundle(now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := appdomain.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Start(ctx, now, b.Manifest.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = d.store.pg.db.ExecContext(ctx, `UPDATE application_processing_jobs SET job=jsonb_set(jsonb_set(job,'{from}',to_jsonb($1::text)),'{to}',to_jsonb($2::text)) WHERE lane='history'`, now.Add(-65*time.Minute).Format(time.RFC3339Nano), now.Add(-55*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	original := d.store.ch.client.Transport
	if original == nil {
		original = http.DefaultTransport
	}
	fired := false
	d.store.ch.client.Transport = appTransport(func(r *http.Request) (*http.Response, error) {
		// Reading the body to identify INSERT requires restoring it for the real request.
		isInsert := false
		if r.GetBody != nil {
			body, _ := r.GetBody()
			buf := make([]byte, 64)
			n, _ := body.Read(buf)
			body.Close()
			isInsert = strings.HasPrefix(string(buf[:n]), "INSERT INTO application_observations")
		}
		resp, e := original.RoundTrip(r)
		if isInsert && !fired && e == nil {
			fired = true
			resp.Body.Close()
			return nil, errors.New("injected lost write acknowledgement")
		}
		return resp, e
	})
	if _, err = d.Step(ctx, "history", now, b); err == nil {
		t.Fatal("expected injected acknowledgement loss")
	}
	if !fired {
		t.Fatal("write fault did not fire")
	}
	state, err := d.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.History.Processed != 0 || state.History.After.Timestamp != "" || state.History.Retries != 1 {
		t.Fatalf("failed write advanced progress: %+v", state)
	}
	if err = d.Control(ctx, "pause"); err != nil {
		t.Fatal(err)
	}
	state, _ = d.State(ctx)
	if state.History.RequestedControl != "pause" || state.History.Status != "running" {
		t.Fatal("pending batch pause must await commit")
	}
	d.store.ch.client.Transport = original
	restarted := &applicationDB{store: d.store}
	if _, err = restarted.Step(ctx, "history", now, b); err != nil {
		t.Fatal(err)
	}
	state, _ = restarted.State(ctx)
	if state.History.Status != "paused" || state.History.Processed != 3 || state.History.RequestedControl != "" {
		t.Fatalf("recovery/pause failed: %+v", state.History)
	}
	q := appdomain.Query{From: now.Add(-2 * time.Hour), To: now, SensorID: sensor}
	report, err := d.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if report.ObservationCount != 3 {
		t.Fatalf("replay double counted: %+v", report)
	}
	if err = d.Control(ctx, "resume"); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Step(ctx, "history", now, b); err != nil {
		t.Fatal(err)
	}
	state, _ = d.State(ctx)
	if state.History.Status != "completed" || state.History.Processed != 3 {
		t.Fatalf("resume cursor incorrect: %+v", state.History)
	}
	// Simulate PostgreSQL becoming unavailable after ClickHouse acknowledges a
	// successful result insert. A fresh process must recover the prepared page.
	if err = d.Start(ctx, now, b.Manifest.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = d.store.pg.db.ExecContext(ctx, `UPDATE application_processing_jobs SET job=jsonb_set(jsonb_set(job,'{from}',to_jsonb($1::text)),'{to}',to_jsonb($2::text)) WHERE lane='history'`, now.Add(-65*time.Minute).Format(time.RFC3339Nano), now.Add(-55*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	closed := false
	d.store.ch.client.Transport = appTransport(func(r *http.Request) (*http.Response, error) {
		isInsert := false
		if r.GetBody != nil {
			body, _ := r.GetBody()
			buf := make([]byte, 64)
			n, _ := body.Read(buf)
			body.Close()
			isInsert = strings.HasPrefix(string(buf[:n]), "INSERT INTO application_observations")
		}
		response, e := original.RoundTrip(r)
		if isInsert && !closed && e == nil {
			closed = true
			_ = d.store.pg.db.Close()
		}
		return response, e
	})
	if _, err = d.Step(ctx, "history", now, b); err == nil {
		t.Fatal("expected cursor-store outage")
	}
	d.store.ch.client.Transport = original
	restored, e := NewPostgresStore(PostgresOptions{DSN: d.store.pg.dsn})
	if e != nil {
		t.Fatal(e)
	}
	d.store.pg = restored
	if !closed {
		t.Fatal("PostgreSQL outage injection did not fire")
	}
	if _, err = d.store.pg.db.ExecContext(ctx, "UPDATE application_processing_jobs SET lease_until=now()-interval '1 second' WHERE lane='history'"); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Step(ctx, "history", now, b); err != nil {
		t.Fatal(err)
	}
	state, _ = d.State(ctx)
	if state.History.Processed != 3 || state.History.Status != "completed" {
		t.Fatalf("cursor-store recovery failed: %+v", state.History)
	}
	// A low-priority ordinary scan visits old events but must not append the
	// same classifications again, regardless of their current revision.
	var beforeRows, afterRows int
	countRows := func() int {
		data, e := d.store.ch.query(ctx, "SELECT count() AS count FROM application_observations WHERE sensor_id="+chQuote(sensor)+" FORMAT JSONEachRow")
		if e != nil {
			t.Fatal(e)
		}
		n, e := decodeSingleCount(data)
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	beforeRows = countRows()
	if _, err = d.Step(ctx, "reconcile", now, b); err != nil {
		t.Fatal(err)
	}
	afterRows = countRows()
	if beforeRows != afterRows {
		t.Fatalf("reconcile appended existing results: %d -> %d", beforeRows, afterRows)
	}
	// Realtime failures leave history admission paused until realtime recovers.
	d.store.ch.client.Transport = appTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("injected source outage") })
	if _, err = d.Step(ctx, "realtime", now, b); err == nil {
		t.Fatal("source outage ignored")
	}
	d.store.ch.client.Transport = original
	if err = d.Start(ctx, now, b.Manifest.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = d.store.pg.db.ExecContext(ctx, `UPDATE application_processing_jobs SET job=jsonb_set(jsonb_set(job,'{from}',to_jsonb($1::text)),'{to}',to_jsonb($2::text)) WHERE lane='history'`, now.Add(-65*time.Minute).Format(time.RFC3339Nano), now.Add(-55*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	_, blocked, _, err := d.acquire(ctx, "history", now, b.Manifest.Version)
	if err != nil || blocked != "" {
		t.Fatal("history admitted during realtime failure")
	}
	// Realtime scans bounded one-minute slices. Recovery is complete only when
	// the retained scan window is drained, rather than after its first page.
	for i := 0; ; i++ {
		more, stepErr := d.Step(ctx, "realtime", now, b)
		if stepErr != nil {
			t.Fatal(stepErr)
		}
		if !more {
			break
		}
		if i >= 10 {
			t.Fatal("realtime recovery did not finish bounded fixture window")
		}
	}
	if err = d.Control(ctx, "cancel"); err != nil {
		t.Fatal(err)
	}
	// An expired lease can be acquired elsewhere; an unexpired lease cannot.
	if err = d.Start(ctx, now, b.Manifest.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = d.store.pg.db.ExecContext(ctx, `UPDATE application_processing_jobs SET job=jsonb_set(jsonb_set(job,'{from}',to_jsonb($1::text)),'{to}',to_jsonb($2::text)) WHERE lane='history'`, now.Add(-65*time.Minute).Format(time.RFC3339Nano), now.Add(-55*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	_, owner, _, err := d.acquire(ctx, "history", now, b.Manifest.Version)
	if err != nil || owner == "" {
		t.Fatalf("acquire: %s %v", owner, err)
	}
	_, other, _, err := restarted.acquire(ctx, "history", now, b.Manifest.Version)
	if err != nil || other != "" {
		t.Fatal("concurrent lease acquired")
	}
	if _, err = d.store.pg.db.ExecContext(ctx, "UPDATE application_processing_jobs SET lease_until=now()-interval '1 second' WHERE lane='history'"); err != nil {
		t.Fatal(err)
	}
	if err = d.Control(ctx, "cancel"); err != nil {
		t.Fatal(err)
	}
	state, _ = d.State(ctx)
	if state.History.Status != "cancelled" {
		t.Fatal("expired lease cancellation failed")
	}
	// Low-priority work yields to realtime, but realtime ignores history leases.
	if err = d.Start(ctx, now, b.Manifest.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = d.store.pg.db.ExecContext(ctx, `UPDATE application_processing_jobs SET job=jsonb_set(jsonb_set(job,'{from}',to_jsonb($1::text)),'{to}',to_jsonb($2::text)) WHERE lane='history'`, now.Add(-65*time.Minute).Format(time.RFC3339Nano), now.Add(-55*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	_, rt, _, err := d.acquire(ctx, "realtime", now.Add(time.Second), b.Manifest.Version)
	if err != nil || rt == "" {
		t.Fatal("realtime blocked by history")
	}
	_, owner, _, err = d.acquire(ctx, "history", now, b.Manifest.Version)
	if err != nil || owner != "" {
		t.Fatal("history failed to yield")
	}
}
