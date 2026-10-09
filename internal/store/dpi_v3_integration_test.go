package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDPIOverviewV3IgnoresExpiredLegacyCursorPostgres(t *testing.T) {
	s := activityV3PrivatePostgres(t)
	ctx := context.Background()
	t.Setenv("PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3", "true")
	if _, e := s.ensureActivityV3Cutover(ctx); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, e := s.pg.db.Exec(`CREATE TABLE activity_chart_read_model_cursor_v2(id int,updated_at timestamptz);INSERT INTO activity_chart_read_model_cursor_v2 VALUES(1,now()-interval '5 days')`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.pg.db.Exec(`INSERT INTO read_model_runtime_state(name,state) VALUES('activity-v3-5m',jsonb_build_object('as_of',$1::text))`, now.Format(time.RFC3339Nano)); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "activity_chart_bucket_facts_v2") {
			t.Error("DPI queried legacy facts")
		}
		io.WriteString(w, "{\"event_count\":7,\"active_ip_count\":2,\"protocol_flow_count\":1,\"count\":0}\n")
	}))
	defer server.Close()
	s.ch = &ClickHouseStore{dsn: server.URL, client: server.Client()}
	got, e := s.GetDPIOverview(ctx, ActivityQuery{Window: "1h"})
	if e != nil || got.EventCount != 7 || got.StatisticsAsOf != now.Format(time.RFC3339Nano) {
		t.Fatalf("legacy cursor gated V3: %+v %v", got, e)
	}
}
