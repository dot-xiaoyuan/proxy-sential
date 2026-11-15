package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func recoveryFixture() (discovery.Observation, HardwareDHCPRecovery) {
	line := "1794483283.060434\tuid-1\t10.0.0.2\t00:11:22:33:44:55\tREQUEST,ACK\t3600.000000\t201/7\tF\tH3C. H3C WA5320H"
	sum := sha256.Sum256([]byte(line))
	digest := hex.EncodeToString(sum[:])
	at := time.Unix(1794483283, 60434000).UTC()
	o := discovery.Observation{ID: "obs", EventID: "zeek-" + digest[:24], SourceID: "passive:sensor:eth0", Origin: "dhcp", Node: "sensor", Site: "campus", Domain: "eth0", IP: "10.0.0.2", MAC: "00:11:22:33:44:55", ObservedAt: at, ValidUntil: at.Add(time.Hour), Evidence: normalized.Event{
		Source: "zeek", SourceEventType: "dhcp", EventID: "zeek-" + digest[:24], Timestamp: at.Format(time.RFC3339Nano),
		RawRef:  map[string]any{"backend": "zeek", "log": "dhcp", "line_offset": 9},
		Payload: map[string]any{"uids": "uid-1", "assigned_addr": "10.0.0.2", "client_mac": "00:11:22:33:44:55", "msg_types": "REQUEST,ACK", "lease_time": "3600.000000", "vendor_class": "H3C. H3C WA5320H"},
	}}
	return o, HardwareDHCPRecovery{Header: "#separator \\x09\n#fields\tts\tuids\tassigned_addr\tmac\tmsg_types\tlease_time\tcapture_vlan\tdiscovery_scope_conflict\tvendor_class\n", RawLine: line, RawSHA256: digest}
}

func TestHardwareDHCPRecoveryVerifiesOriginalAndPreservesTime(t *testing.T) {
	o, p := recoveryFixture()
	got, err := RecoverHardwareDHCPObservation(o, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.VLAN != "201/7" || got.Key() == o.Key() || !got.ObservedAt.Equal(o.ObservedAt) || !got.ValidUntil.Equal(o.ValidUntil) {
		t.Fatalf("bad recovery %+v", got)
	}
	if o.VLAN != "" || o.Evidence.Payload["dhcp_capture_vlan"] != nil {
		t.Fatal("mutated original")
	}
	f, err := discovery.HardwareFactFromObservation(got)
	if err != nil || f == nil || len(f.Signals) != 1 || f.Signals[0].Value != "WA5320H" {
		t.Fatalf("model lost %+v %v", f, err)
	}
}

func TestHardwareDHCPRecoveryRejectsMismatchedEvidence(t *testing.T) {
	for _, name := range []string{"hash", "event", "mac", "ip", "model", "lease", "scope", "withdrawn", "vlan", "newline"} {
		t.Run(name, func(t *testing.T) {
			o, p := recoveryFixture()
			switch name {
			case "hash":
				p.RawSHA256 = strings.Repeat("0", 64)
			case "event":
				o.EventID = "zeek-another"
			case "mac":
				o.MAC = "00:11:22:33:44:66"
			case "ip":
				o.IP = "10.0.0.3"
			case "model":
				o.Evidence.Payload["vendor_class"] = "H3C. H3C WA7220"
			case "lease":
				o.Evidence.Payload["lease_time"] = "7200"
			case "scope":
				o.Evidence.Observer = map[string]any{"capture_scope_issue": "conflict"}
			case "withdrawn":
				o.Withdrawn = true
			case "vlan":
				o.VLAN = "202"
			case "newline":
				p.RawLine += "\n" + p.RawLine
			}
			if _, err := RecoverHardwareDHCPObservation(o, p); err == nil {
				t.Fatal("accepted mismatched original")
			}
		})
	}
}

func TestHardwareDHCPRecoveryPostgresCorrectionAndRetry(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not configured")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("dhcp_recovery_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + "; SET search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	for _, name := range []string{"241_passive_hardware_projection.sql", "242_passive_hardware_claim_index.sql"} {
		b, err := os.ReadFile(filepath.Join("../../migrations/postgres", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(b)); err != nil {
			t.Fatal(err)
		}
	}
	_, err = db.Exec(`CREATE TABLE discovery_observation_latest(
 device_key text,source_id text,origin text,service_type text,port text,id text,
 observed_at timestamptz,valid_until timestamptz,withdrawn boolean,data jsonb,
 PRIMARY KEY(device_key,source_id,origin,service_type,port))`)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, scenario := range []string{"normal", "source_changed", "target_newer", "target_revoked", "rollback"} {
		t.Run(scenario, func(t *testing.T) {
			if _, err = db.Exec("TRUNCATE discovery_observation_latest,passive_hardware_facts,passive_hardware_dirty"); err != nil {
				t.Fatal(err)
			}
			o, proof := recoveryFixture()
			raw, _ := json.Marshal(o)
			_, err = db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,'dhcp','','',$3,$4,$5,false,$6)`, o.Key(), o.SourceID, o.ID, o.ObservedAt, o.ValidUntil, string(raw))
			if err != nil {
				t.Fatal(err)
			}
			var originalJSON []byte
			if err = db.QueryRow("SELECT data::text FROM discovery_observation_latest").Scan(&originalJSON); err != nil {
				t.Fatal(err)
			}
			e := makeHardwareRepairEntry([5]string{o.Key(), o.SourceID, "dhcp", "", ""}, originalJSON, o)
			e.DHCPRecovery = &proof
			m := HardwareRepairManifest{SchemaVersion: HardwareRepairSchema, Window: HardwareRepairWindow{Sensor: o.Node, From: o.ObservedAt.Add(-time.Hour), Until: o.ObservedAt.Add(time.Hour)}, SnapshotAt: o.ObservedAt.Add(2 * time.Hour), Entries: []HardwareRepairEntry{e}}
			restored, err := RecoverHardwareDHCPObservation(o, proof)
			if err != nil {
				t.Fatal(err)
			}
			// Simulate the previously extracted address-only DHCP fact.
			old := o
			old.Evidence.Payload = map[string]any{}
			if err = discovery.EnqueueHardwareObservations(ctx, db, []discovery.Observation{old}); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "source_changed":
				_, err = db.Exec("UPDATE discovery_observation_latest SET data=jsonb_set(data,'{id}','\"newer\"')")
			case "target_newer", "target_revoked":
				latest := restored
				latest.ID = "newer"
				latest.EventID = "newer"
				latest.ObservedAt = latest.ObservedAt.Add(time.Minute)
				latest.Withdrawn = scenario == "target_revoked"
				b, _ := json.Marshal(latest)
				_, err = db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,'dhcp','','',$3,$4,$5,$6,$7)`, latest.Key(), latest.SourceID, latest.ID, latest.ObservedAt, latest.ValidUntil, latest.Withdrawn, string(b))
			case "rollback":
				_, err = db.Exec("ALTER TABLE passive_hardware_facts ADD CONSTRAINT fail_new_scope CHECK (vlan='')")
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := ApplyHardwareRepairBatch(ctx, db, m, 0, 1)
			if scenario == "rollback" {
				if err == nil {
					t.Fatal("injected failure did not abort")
				}
				var key string
				db.QueryRow("SELECT device_key FROM discovery_observation_latest").Scan(&key)
				if key != o.Key() {
					t.Fatal("latest correction escaped rolled back transaction")
				}
				if _, err = db.Exec("ALTER TABLE passive_hardware_facts DROP CONSTRAINT fail_new_scope"); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 {
				t.Fatalf("%+v", out)
			}
			if scenario == "source_changed" {
				if out[0].Reason != "source_changed" {
					t.Fatalf("%+v", out)
				}
				return
			}
			var n int
			if err = db.QueryRow("SELECT count(*) FROM discovery_observation_latest").Scan(&n); err != nil || n != 1 {
				t.Fatalf("duplicate latest %d %v", n, err)
			}
			if scenario != "normal" {
				if out[0].Reason != "superseded_by_current_observation" {
					t.Fatalf("%+v", out)
				}
				if err = db.QueryRow("SELECT count(*) FROM passive_hardware_facts WHERE vlan<>''").Scan(&n); err != nil || n != 0 {
					t.Fatal("revived old product")
				}
				return
			}
			if out[0].Status != "admitted" {
				t.Fatalf("%+v", out)
			}
			if err = db.QueryRow("SELECT count(*) FROM passive_hardware_facts WHERE NOT revoked AND vlan='201/7'").Scan(&n); err != nil || n != 1 {
				t.Fatalf("missing corrected fact %d %v", n, err)
			}
			if err = db.QueryRow("SELECT count(*) FROM passive_hardware_facts WHERE NOT revoked AND vlan=''").Scan(&n); err != nil || n != 0 {
				t.Fatal("old scoped fact active")
			}
			retry, err := ApplyHardwareRepairBatch(ctx, db, m, 0, 1)
			if err != nil || len(retry) != 1 || retry[0].Reason != "already_recovered" {
				t.Fatalf("retry %+v %v", retry, err)
			}
			if err = db.QueryRow("SELECT count(*) FROM passive_hardware_facts").Scan(&n); err != nil || n != 2 {
				t.Fatal("retry duplicated facts")
			}
		})
	}
}
