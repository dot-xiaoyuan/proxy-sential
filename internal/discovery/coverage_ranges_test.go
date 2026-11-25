package discovery

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

func TestReportRangesRejectInvalidIPv4Scope(t *testing.T) {
	for _, input := range []string{`[]`, `null`, `[{"range":"10.1.2.4/24","device_type":"a"}]`, `[{"range":"::1","device_type":"a"}]`, `[{"range":"10.0.0.2-10.0.0.1","device_type":"a"}]`, `[{"range":"192.0.2.1","device_type":""}]`} {
		if _, _, err := parseReportRanges(input); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func TestReportRangesPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TEMP TABLE passive_census_runtime(sensor_id text,scope_version text,available_from timestamptz,last_source_at timestamptz,last_success_at timestamptz,oldest_pending_at timestamptz);
 CREATE TEMP TABLE passive_census_identifier_current(sensor_id text,kind text,ip_family integer,value text,last_seen timestamptz);
 INSERT INTO passive_census_runtime VALUES ('s','capture-v1',now()-interval '3 days',now(),now(),NULL);
 INSERT INTO passive_census_identifier_current VALUES
 ('s','ip',4,'10.1.1.2',now()-interval '1h'),('s','ip',4,'10.1.1.2',now()-interval '2h'),
 ('s','ip',4,'10.1.1.3',now()-interval '1h'),('s','ip',4,'10.1.1.1',now()-interval '2 days'),
 ('s','ip',4,'10.1.1.9',now()-interval '1h'),('s','ip',4,'10.1.1.4',now()+interval '1h'),
 ('other','ip',4,'10.1.1.1',now()-interval '1h'),('s','ip',6,'::1',now()-interval '1h'),('s','mac',0,'aa:bb:cc:dd:ee:ff',now()-interval '1h');`)
	if err != nil {
		t.Fatal(err)
	}
	cfg := `[{"range":"10.1.1.0/30","device_type":"打印机"},{"range":"10.1.1.2-10.1.1.4","device_type":"摄像头"},{"range":"10.1.2.1","device_type":"服务器"}]`
	for _, tc := range []struct {
		hours  int
		total  int64
		status string
	}{{24, 2, "ready"}, {168, 3, "partial"}, {720, 3, "partial"}} {
		r, err := readPlannedIPv4(context.Background(), db, "s", time.Duration(tc.hours)*time.Hour, cfg)
		if err != nil || r == nil || r.VisibleIPv4 == nil || *r.VisibleIPv4 != tc.total || r.Status != tc.status || r.Ranges[0].VisibleIPv4 != tc.total || r.Ranges[1].VisibleIPv4 != 2 || r.Ranges[2].VisibleIPv4 != 0 || r.CaptureVersion != "capture-v1" || r.AvailableFrom == nil || r.AsOf == nil || r.Version == "" {
			t.Fatalf("%dh result %+v (%v)", tc.hours, r, err)
		}
	}
	r, err := readPlannedIPv4(context.Background(), db, "absent", 24*time.Hour, cfg)
	if err != nil || r.Status != "initializing" || r.VisibleIPv4 != nil {
		t.Fatalf("missing source %+v %v", r, err)
	}
	if r, err = readPlannedIPv4(context.Background(), nil, "s", 24*time.Hour, ""); err != nil || r != nil {
		t.Fatalf("disabled %+v %v", r, err)
	}
}
