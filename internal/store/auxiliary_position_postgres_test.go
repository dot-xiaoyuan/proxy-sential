package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/pagination"
)

func TestAuxiliaryPostgresPositionsMatchFilteredTraceAndRiskIndexes(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, statement := range []string{
		`CREATE TEMP TABLE device_address_leases(endpoint_id text,action text,ip inet,observed_at timestamptz,event_id text)`,
		`CREATE TEMP TABLE account_sessions(endpoint_id text,source text,session_id text,ip inet,account_id text,access_id text,started_at timestamptz,ended_at timestamptz,identity_confidence float8,policy_metadata jsonb)`,
		`CREATE TEMP TABLE endpoint_inventory_lookup(endpoint_id text,updated_at timestamptz)`,
		`CREATE TEMP TABLE endpoint_state_watermark(singleton bool,bootstrap_complete bool,last_error text,last_success_at timestamptz,updated_at timestamptz)`,
		`INSERT INTO endpoint_state_watermark VALUES(true,true,'',now(),now())`,
		`CREATE TEMP TABLE endpoint_recognition_jobs(processed_generation int,dirty_generation int)`,
		`CREATE TEMP TABLE stream_risk_fresh_cutovers(sensor_id text,accepted_after timestamptz)`,
		`CREATE TEMP TABLE stream_risk_current(sensor_id text,subject_type text,subject_id text,level text,score int,evaluated_at timestamptz,observed_at timestamptz)`,
		`CREATE TEMP TABLE risk_feature_dirty_subjects(sensor_id text,subject_type text,subject_id text)`,
	} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	id := "endpoint-a"
	if _, err = db.ExecContext(ctx, `INSERT INTO endpoint_inventory_lookup VALUES($1,$2)`, id, at); err != nil {
		t.Fatal(err)
	}
	for index, event := range []string{"a", "b", "c", "d"} {
		if _, err = db.ExecContext(ctx, `INSERT INTO device_address_leases VALUES($1,'ack','192.0.2.1',$2,$3)`, id, at.Add(-time.Duration(index)*time.Minute), event); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO account_sessions VALUES($1,'radius','session-a','192.0.2.1','alice','port-a',$2,NULL,.9,'{}')`, id, at.Add(-90*time.Second)); err != nil {
		t.Fatal(err)
	}
	pg := &PostgresStore{db: db}
	q := EndpointObservationQuery{Kind: "ip", AsOf: at.Format(time.RFC3339Nano), Limit: 20}
	metadata, err := pg.EndpointObservationMetadata(ctx, id, q)
	if err != nil || metadata.Total != 5 {
		t.Fatalf("metadata=%+v err=%v", metadata, err)
	}
	baseline, err := pg.ListEndpointObservations(ctx, id, q)
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{1, 2, 3} {
		pages := (len(baseline.Items) + limit - 1) / limit
		q.Limit = limit
		for number := pages; number >= 1; number-- {
			position, err := pg.PositionEndpointObservations(ctx, id, q, number)
			if err != nil {
				t.Fatal(err)
			}
			q.Cursor = position.Cursor
			result, err := pg.ListEndpointObservations(ctx, id, q)
			if err != nil {
				t.Fatal(err)
			}
			start := (number - 1) * limit
			end := min(start+limit, len(baseline.Items))
			if !reflect.DeepEqual(result.Items, baseline.Items[start:end]) {
				t.Fatalf("page=%d limit=%d result=%+v baseline=%+v", number, limit, result.Items, baseline.Items[start:end])
			}
		}
		q.Cursor = ""
		if _, err = pg.PositionEndpointObservations(ctx, id, q, pages+1); !errors.Is(err, pagination.ErrPageOutOfRange) {
			t.Fatalf("accepted empty trace page: %v", err)
		}
	}
	q.Source = "radius"
	q.Limit = 1
	metadata, err = pg.EndpointObservationMetadata(ctx, id, q)
	if err != nil || metadata.Total != 1 {
		t.Fatalf("source metadata=%+v err=%v", metadata, err)
	}
	if _, err = pg.PositionEndpointObservations(ctx, id, q, 2); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatalf("accepted successor of full final page: %v", err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO device_address_leases VALUES($1,'ack','192.0.2.1',$2,'future')`, id, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	q.Source = ""
	metadata, err = pg.EndpointObservationMetadata(ctx, id, q)
	if err != nil || metadata.Total != 5 {
		t.Fatalf("snapshot included later fact: %+v %v", metadata, err)
	}
	cutoff := at.Add(-time.Hour)
	for _, statement := range []string{`INSERT INTO stream_risk_fresh_cutovers VALUES('sensor-a',$1)`, `INSERT INTO stream_risk_current VALUES('sensor-a','account','alice','high',80,$2,$2),('sensor-a','account','bob','high',70,$2,$2),('sensor-a','account','dirty','high',90,$2,$2),('sensor-a','account','expired','high',90,$2,$1),('sensor-b','account','other','high',90,$2,$2)`, `INSERT INTO risk_feature_dirty_subjects VALUES('sensor-a','account','dirty')`} {
		args := []any{}
		if statement == `INSERT INTO stream_risk_fresh_cutovers VALUES('sensor-a',$1)` {
			args = []any{cutoff}
		} else if strings.HasPrefix(statement, "INSERT INTO stream_risk_current ") {
			args = []any{cutoff, at}
		}
		if _, err = db.ExecContext(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	riskMetadata, err := pg.StreamRiskCurrentMetadata(ctx, "sensor-a", "account", "high")
	if err != nil || riskMetadata.Total != 2 {
		t.Fatalf("risk metadata=%+v err=%v", riskMetadata, err)
	}
	p, err := pg.PositionStreamRiskCurrent(ctx, "sensor-a", "account", "high", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	var cursor streamRiskCursor
	raw, _ := base64.RawURLEncoding.DecodeString(p.Cursor)
	if json.Unmarshal(raw, &cursor) != nil || cursor.ID != "alice" || cursor.Score != 80 || !cursor.Cutoff.Equal(cutoff) {
		t.Fatalf("wrong risk cursor %+v", cursor)
	}
	if _, err = pg.PositionStreamRiskCurrent(ctx, "sensor-a", "account", "high", 3, 1); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatalf("accepted empty risk page: %v", err)
	}
}
