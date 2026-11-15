package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHardwareIoTAdmissionUsesTypesAcrossProtocols(t *testing.T) {
	for _, q := range []DeviceQuery{{HardwareV2: true, View: "iot"}, {HardwareV2: true, Capability: "dumb"}} {
		s, err := buildIndexedDeviceSelection(q)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(s.CTE, "origin IN ('dns_sd','ssdp','ws_discovery')") || !strings.Contains(s.CTE, "product_types") || s.PageProfiles {
			t.Fatal("IoT admission still depends on protocol or omits current clues")
		}
	}
	s, _ := buildIndexedDeviceSelection(DeviceQuery{View: "iot"})
	if !strings.Contains(s.CTE, "origin IN ('dns_sd','ssdp','ws_discovery')") {
		t.Fatal("184 legacy admission changed")
	}
}

func TestHardwarePostgresIoTListMetadataExportAgree(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute)
	names := []string{"door", "camera", "ap", "router", "printer_clue", "old_printer", "switch_product", "sensor_product", "wrong_product_scope", "phone_product"}
	for i, name := range names {
		o := hardwareTestObservation(at)
		o.ID = name
		o.EventID = name
		o.Evidence.EventID = name
		o.MAC = fmt.Sprintf("02:11:22:33:44:%02x", i)
		o.IP = fmt.Sprintf("10.0.0.%d", i+2)
		o.ValidUntil = at.Add(time.Hour)
		o.Evidence.Payload["claimed_ip"] = o.IP
		o.Evidence.Payload["claimed_mac"] = o.MAC
		o.Evidence.Payload["l2_source_mac"] = o.MAC
		switch name {
		case "door", "camera":
			if name == "camera" {
				o.ModelName = "DS-2CD2143G2-I"
				o.Evidence.Payload["product_model"] = o.ModelName
			}
			enqueueHardwareTest(t, db, o)
			processHardwareTest(t, db)
		case "ap", "router":
			o.Origin = "dhcp"
			o.Capabilities = []string{"routing"}
			o.Evidence.Payload = nil
			kind := "access_point"
			if name == "router" {
				kind = "router"
			}
			if _, err := db.Exec("INSERT INTO endpoint_recognition_summary VALUES($1,$2,'','{}',0.95,false,$3)", "mac:"+o.MAC, kind, at); err != nil {
				t.Fatal(err)
			}
		case "printer_clue", "old_printer":
			o.Origin = "dns_sd"
			o.Evidence.Payload = nil
			o.Capabilities = []string{"printing"}
			o.Confidence = "strong"
			if name == "old_printer" {
				o.ValidUntil = at
			}
		default:
			o.Origin = "snmp"
			o.MAC = ""
			o.Evidence.Payload = nil
			kind := "switch"
			if name != "switch_product" {
				kind = "environment_monitor"
			}
			o.ProductClue = &IPProductClue{IP: o.IP, SensorID: o.Node, Site: o.Site, Domain: o.Domain, VLAN: o.VLAN, VRF: o.VRF, EventID: o.EventID, Type: kind, ProductStatus: "identified", ObservedAt: at, Attribution: "response_ip"}
			if name == "phone_product" {
				o.Origin = "sip"
				o.ProductClue.Type, o.ProductClue.Attribution = "voip_phone", "request_ip"
			}
			if name == "wrong_product_scope" {
				o.ProductClue.VLAN = "999"
			}
		}
		raw, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec("INSERT INTO discovery_observation_latest VALUES($1,$2,$3,$4,$5,false,$6)", o.ID, o.Key(), o.Origin, o.ObservedAt, o.ValidUntil, raw); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	repo := Repository{DB: db, HardwareV2: true}
	for _, q := range []DeviceQuery{{Mode: "passive", View: "iot"}, {Mode: "passive", Capability: "dumb"}, {Mode: "passive", View: "iot", Export: true}} {
		meta, err := repo.DevicesIndexedMetadataSnapshot(ctx, tx, q)
		if err != nil {
			t.Fatal(err)
		}
		page, err := repo.DevicesIndexedSnapshot(ctx, tx, q)
		if err != nil {
			t.Fatal(err)
		}
		items := page["items"].([]DeviceView)
		if len(items) != 5 || meta.Total != 5 || meta.Identified != 2 || meta.Candidate != 3 {
			t.Fatalf("q=%+v metadata=%+v items=%d", q, meta, len(items))
		}
	}
	for _, kind := range []string{"access_point", "router", "switch", "environment_monitor", "voip_phone"} {
		q := DeviceQuery{Mode: "passive", DeviceType: kind}
		meta, err := repo.DevicesIndexedMetadataSnapshot(ctx, tx, q)
		if err != nil {
			t.Fatal(err)
		}
		if (kind == "switch" || kind == "environment_monitor" || kind == "voip_phone") && (len(meta.IPProductTypes) != 1 || meta.IPProductTypes[0].Count != 1) {
			t.Fatalf("product clue counts lost: %+v", meta)
		}
		if meta.Total != 1 || meta.Identified != 0 {
			t.Fatalf("%s metadata=%+v", kind, meta)
		}
	}
}
