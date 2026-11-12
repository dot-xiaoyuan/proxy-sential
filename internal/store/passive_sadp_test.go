package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func sadpTestEvent(status, subjectMAC, claimedIP, claimedMAC, model string) (eventKind string, eventIP, eventMAC string, payload map[string]any) {
	return "sadp", "10.126.253.1", subjectMAC, map[string]any{
		"is_response": true, "message_type": "probe_match", "product_model": model,
		"claimed_ip": claimedIP, "claimed_mac": claimedMAC, "l2_source_mac": subjectMAC,
		"identity_status": status, "payload_sha256": "9c0e739b3124b05acae5ec96977d26699fa6a2cd07bb1d070608e77783b2f702",
	}
}

func TestPassiveSADPRequiresVerifiedAttributionForType(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("10.126.0.0/16")
	kind, ip, mac, payload := sadpTestEvent("direct_l2", "08:54:11:13:c1:84", "10.126.253.1", "08:54:11:13:c1:84", "DS-K1T6QT-F72M")
	event := passiveTestEvent(kind, ip, mac, payload)
	event.Source = "packet-sidecar"
	event.Flow = map[string]any{"src_ip": ip, "dst_ip": "239.255.255.250"}
	got, reason := passiveObservation(event, scope)
	if reason != "" || got.DeviceType != "access_control" || got.ModelName != "DS-K1T6QT-F72M" || got.MAC != mac || got.Origin != "sadp" {
		t.Fatalf("verified model lost: reason=%q observation=%+v", reason, got)
	}
	for _, sample := range []struct{ status, subjectMAC, claimedIP, frameMAC string }{
		{"ip_mismatch", "", "10.126.253.2", "08:54:11:13:c1:84"},
		{"l2_mismatch", "", "10.126.253.1", "00:11:22:33:44:55"},
	} {
		_, ip, mac, payload = sadpTestEvent(sample.status, sample.subjectMAC, sample.claimedIP, "08:54:11:13:c1:84", "DS-K1T6QT-F72M")
		payload["l2_source_mac"] = sample.frameMAC
		event = passiveTestEvent("sadp", ip, mac, payload)
		event.Source = "packet-sidecar"
		event.Flow = map[string]any{"src_ip": ip, "dst_ip": "239.255.255.250"}
		got, reason = passiveObservation(event, scope)
		if reason != "" || got.DeviceType != "" || got.MAC != "" {
			t.Fatalf("unverified model became an effective type: reason=%q observation=%+v", reason, got)
		}
	}
}

func TestPassiveSADPObservedProductModelsReachDiscovery(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("10.126.0.0/16")
	for _, sample := range []struct{ model, want string }{
		{"DS-7908N-R4(C)", "recorder"},
		{"DS-8832N-R8(C)", "recorder"},
		{"DS-7916N-K4", "recorder"},
		{"iDS-2DC3A40BX-DE", "camera"},
		{"DS-7908N", ""},
	} {
		kind, ip, mac, payload := sadpTestEvent("direct_l2", "08:54:11:13:c1:84", "10.126.253.1", "08:54:11:13:c1:84", sample.model)
		event := passiveTestEvent(kind, ip, mac, payload)
		event.Source = "packet-sidecar"
		event.Flow = map[string]any{"src_ip": ip, "dst_ip": "239.255.255.250"}
		got, reason := passiveObservation(event, scope)
		if reason != "" || got.DeviceType != sample.want {
			t.Errorf("%s: reason=%q type=%q, want %q", sample.model, reason, got.DeviceType, sample.want)
		}
	}
}

func TestPassiveSADPBindingRequiresSameScopeAndEventTime(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("10.126.0.0/16")
	_, ip, mac, payload := sadpTestEvent("l2_mismatch", "", "10.126.253.1", "08:54:11:13:c1:84", "DS-K1T6QT-F72M")
	payload["l2_source_mac"] = "00:11:22:33:44:55"
	event := passiveTestEvent("sadp", ip, mac, payload)
	event.Source = "packet-sidecar"
	event.Flow = map[string]any{"src_ip": ip, "dst_ip": "239.255.255.250"}
	event.Subject["campus_id"] = "campus-204"
	event.Observer["sensor_id"] = "campus-204"
	event.Observer["interface"] = "enp3s0f0"
	observation, reason := passiveObservation(event, scope)
	if reason != "" {
		t.Fatal(reason)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("FROM discovery_observation_latest").WithArgs("10.126.253.1", "campus-204", "campus-204", "enp3s0f0", "", observation.ObservedAt).WillReturnRows(sqlmock.NewRows([]string{"mac"}).AddRow("08:54:11:13:c1:84"))
	verified, err := verifySADPBinding(context.Background(), db, observation)
	if err != nil || verified.DeviceType != "access_control" || verified.MAC != "08:54:11:13:c1:84" {
		t.Fatalf("matching ARP did not verify model: observation=%+v err=%v", verified, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	if !verified.ValidUntil.After(time.Now().Add(-time.Hour)) {
		t.Fatal("verified SADP observation has no useful validity")
	}
}

func TestPassiveSADPConflictingOrLateBindingStaysAClue(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("10.126.0.0/16")
	_, ip, mac, payload := sadpTestEvent("l2_mismatch", "", "10.126.253.1", "08:54:11:13:c1:84", "DS-K1T6QT-F72M")
	payload["l2_source_mac"] = "00:11:22:33:44:55"
	event := passiveTestEvent("sadp", ip, mac, payload)
	event.Source = "packet-sidecar"
	event.Flow = map[string]any{"src_ip": ip}
	event.Subject["campus_id"] = "campus-204"
	event.Observer["sensor_id"] = "campus-204"
	event.Observer["interface"] = "enp3s0f0"
	observation, reason := passiveObservation(event, scope)
	if reason != "" {
		t.Fatal(reason)
	}
	for _, sample := range []struct {
		name string
		rows *sqlmock.Rows
	}{
		{"late or missing", sqlmock.NewRows([]string{"mac"})},
		{"conflicting", sqlmock.NewRows([]string{"mac"}).AddRow("08:54:11:13:c1:84").AddRow("00:11:22:33:44:55")},
	} {
		t.Run(sample.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery(`(?s)FROM discovery_observation_latest.*data->>'site'=\$3.*data->>'domain'=\$4.*observed_at<=\$6`).WithArgs("10.126.253.1", "campus-204", "campus-204", "enp3s0f0", "", observation.ObservedAt).WillReturnRows(sample.rows)
			got, err := verifySADPBinding(context.Background(), db, observation)
			if err != nil || got.MAC != "" || got.DeviceType != "" {
				t.Fatalf("unverified SADP became type: observation=%+v err=%v", got, err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
