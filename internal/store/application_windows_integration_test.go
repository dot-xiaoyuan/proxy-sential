package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"proxy-sentinel/internal/appdomain"
)

func TestApplicationWindowsEmptyBoundaryAndResourceRetry(t *testing.T) {
	d := appIntegrationDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour).Truncate(time.Second)
	sensor := fmt.Sprintf("slice-%d", now.UnixNano())
	t.Cleanup(func() {
		d.store.pg.db.ExecContext(ctx, "DELETE FROM application_processing_batches")
		d.store.pg.db.ExecContext(ctx, "DELETE FROM application_processing_jobs")
		d.store.ch.exec(ctx, "ALTER TABLE normalized_events DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=2")
		cleanupApplicationTestData(ctx, d.store, sensor, false)
	})
	raw, err := appdomain.ExampleBundle(now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := appdomain.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	// The first two slices are empty. 1001 records share the exact next boundary.
	sql := fmt.Sprintf(`INSERT INTO normalized_events(timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,observer_json,payload_json,flow_json,raw_ref_json) SELECT parseDateTime64BestEffort(%s,9),concat('slice-',toString(number)),'v1','test','tls','tls',%s,'10.0.0.1','{}','{"sni":"weixin.qq.com"}','{}','{}' FROM numbers(1001)`, chQuote(from.Add(20*time.Minute).Format(time.RFC3339Nano)), chQuote(sensor))
	if err = d.store.ch.exec(ctx, sql); err != nil {
		t.Fatal(err)
	}
	j := appdomain.Job{ID: sensor, Status: "running", Version: b.Manifest.Version, From: from, To: from.Add(30 * time.Minute)}
	job, _ := json.Marshal(j)
	if _, err = d.store.pg.db.ExecContext(ctx, `INSERT INTO application_processing_jobs(lane,job) VALUES('history',$1)`, job); err != nil {
		t.Fatal(err)
	}
	original := d.store.ch.client.Transport
	if original == nil {
		original = http.DefaultTransport
	}
	d.store.ch.client.Transport = appTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("MEMORY_LIMIT_EXCEEDED") })
	if _, err = d.Step(ctx, "history", now, b); err == nil {
		t.Fatal("memory failure ignored")
	}
	d.store.ch.client.Transport = original
	state, err := d.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.History.ScanSeconds != 300 || state.History.Processed != 0 || state.History.Retries != 1 {
		t.Fatal(state.History)
	}
	// A fresh backend reloads persisted retry width and commits distinct empty batches.
	restart := &applicationDB{store: d.store}
	for i := 0; i < 12; i++ {
		more, err := restart.Step(ctx, "history", now, b)
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
	}
	state, err = restart.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.History.Status != "completed" || state.History.Processed != 1001 {
		t.Fatal(state.History)
	}
	report, err := d.Report(ctx, appdomain.Query{From: from, To: j.To, SensorID: sensor})
	if err != nil {
		t.Fatal(err)
	}
	if report.ObservationCount != 1001 {
		t.Fatal(report.ObservationCount)
	}
}
