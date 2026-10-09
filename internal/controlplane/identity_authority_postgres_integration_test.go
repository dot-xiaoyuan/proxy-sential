package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

func TestIdentityAuthorityNativeExactScopeAndReadCount(t *testing.T) {
	db := srunIsolatedReplayDB(t)
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, statement := range []string{`CREATE TEMP SEQUENCE authority_reads`, `CREATE TEMP TABLE authority_registration(source text,sensor_id text,hours integer)`, `INSERT INTO authority_registration VALUES('srun4k:one','one',6)`, `CREATE TEMP VIEW srun4k_integrations AS SELECT source,sensor_id,(hours+nextval('pg_temp.authority_reads')*0)::integer reconcile_interval_hours FROM authority_registration`} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{operations: &operationsState{db: db}}
	base := store.IdentityScope{Source: "srun4k:one", SensorID: "one"}
	for _, name := range []string{"campus", "domain", "both"} {
		t.Run(name, func(t *testing.T) {
			scope := base
			if name != "domain" {
				scope.CampusID = "foreign-campus"
			}
			if name != "campus" {
				scope.AccessDomain = "foreign-domain"
			}
			if _, registered := s.srunIdentityRegistration(ctx, scope); registered {
				t.Fatal("source/sensor authority was borrowed across scope")
			}
			if err := s.validateIdentitySourceContext(ctx, scope, 21600); err == nil {
				t.Fatal("foreign snapshot scope accepted")
			}
		})
	}
	reader := &replayIdentityReader{}
	s.reader = reader
	s.identityIngest = &identityIngestState{key: "token", batches: map[string]IdentityIngestBatch{}}
	for i, hours := range []int{6, 1} {
		if _, err := db.ExecContext(ctx, `UPDATE authority_registration SET hours=$1`, hours); err != nil {
			t.Fatal(err)
		}
		reader.events = nil
		w := runAuthorityBatch(t, s, authorityBatchRequest(128), fmt.Sprintf("native-authority-%d", i))
		if w.Code != http.StatusAccepted || len(reader.events) != 128 {
			t.Fatalf("batch status=%d events=%d body=%s", w.Code, len(reader.events), w.Body.String())
		}
		for _, event := range reader.events {
			if event.Payload["reconcile_interval_seconds"] != hours*3600 {
				t.Fatal("fresh authority not applied")
			}
		}
		var reads int64
		if err := db.QueryRowContext(ctx, `SELECT last_value FROM pg_temp.authority_reads`).Scan(&reads); err != nil {
			t.Fatal(err)
		}
		if reads != int64(i+1) {
			t.Fatalf("SQL repeated or foreign scope queried: reads=%d want=%d", reads, i+1)
		}
	}
	s.identitySources = []identitySourceRegistration{{IdentityScope: store.IdentityScope{Source: base.Source, SensorID: base.SensorID, CampusID: "explicit", AccessDomain: "wifi"}, IntervalSeconds: 60}}
	if err := s.validateIdentitySourceContext(ctx, s.identitySources[0].IdentityScope, 60); err != nil {
		t.Fatal("explicit registered scope rejected", err)
	}
}

func TestIdentityAuthorityNativeReplayRechecksCurrentSource(t *testing.T) {
	s, _ := srunIsolatedReplayServer(t)
	db := s.operations.db
	scope := store.IdentityScope{Source: "radius", SensorID: "authority", CampusID: "east", AccessDomain: "wifi"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, name := range []string{"removed", "mixed_foreign", "current_interval"} {
		t.Run(name, func(t *testing.T) {
			id := "authority-replay-" + shortToken(12)
			t.Cleanup(func() {
				if _, err := db.ExecContext(context.Background(), `DELETE FROM identity_ingest_batches WHERE batch_id=$1`, id); err != nil {
					t.Error(err)
				}
			})
			events := []normalized.Event{{SchemaVersion: "v1", EventID: "retained-one", Source: scope.Source, Type: "identity", Timestamp: "2026-10-01T03:00:00Z", Observer: map[string]any{"sensor_id": scope.SensorID}, Subject: map[string]any{"campus_id": scope.CampusID, "ip": "192.0.2.1"}, Payload: map[string]any{"access_domain": scope.AccessDomain, "reconcile_interval_seconds": 604800}}}
			if name == "mixed_foreign" {
				raw, _ := json.Marshal(events[0])
				var other normalized.Event
				json.Unmarshal(raw, &other)
				other.Subject["campus_id"] = "foreign"
				other.EventID = "retained-foreign"
				events = append(events, other)
			}
			raw, _ := json.Marshal(events)
			if _, err := db.ExecContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,records_emitted,error_message,received_at,normalized_events) VALUES($1,$2,$3,'failed',$4,$4,'existing failure',now(),$5)`, id, scope.Source, scope.SensorID, len(events), raw); err != nil {
				t.Fatal(err)
			}
			reader := &replayIdentityReader{}
			server := &Server{operations: s.operations, identityIngest: &identityIngestState{db: db}, reader: reader}
			if name != "removed" {
				server.identitySources = []identitySourceRegistration{{IdentityScope: scope, IntervalSeconds: 60}}
			}
			var before, after string
			if err := db.QueryRowContext(ctx, `SELECT row_to_json(b)::text FROM identity_ingest_batches b WHERE batch_id=$1`, id).Scan(&before); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/identity/batches/"+id+"/replay", nil)
			server.handleIdentityBatchReplay(w, request)
			if name == "current_interval" {
				if w.Code != http.StatusOK || len(reader.events) != 1 || reader.events[0].EventID != "retained-one" || reader.events[0].Payload["reconcile_interval_seconds"] != 60 {
					t.Fatalf("valid retained replay changed/lost authority: %d %+v", w.Code, reader.events)
				}
				var persisted []byte
				if err := db.QueryRowContext(ctx, `SELECT normalized_events FROM identity_ingest_batches WHERE batch_id=$1`, id).Scan(&persisted); err != nil {
					t.Fatal(err)
				}
				var original []normalized.Event
				json.Unmarshal(persisted, &original)
				if !reflect.DeepEqual(original[0].Payload["reconcile_interval_seconds"], float64(604800)) {
					t.Fatal("retained source evidence rewritten")
				}
			} else {
				if w.Code != http.StatusForbidden || len(reader.events) != 0 {
					t.Fatalf("unregistered replay ingested: status=%d events=%d", w.Code, len(reader.events))
				}
				if err := db.QueryRowContext(ctx, `SELECT row_to_json(b)::text FROM identity_ingest_batches b WHERE batch_id=$1`, id).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if before != after {
					t.Fatal("rejected replay changed retained batch")
				}
			}
		})
	}
}
