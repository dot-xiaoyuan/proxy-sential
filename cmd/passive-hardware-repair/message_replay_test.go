package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func messageReplayFixture(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "device_dhcp_message.log")
	raw, _ := json.Marshal(map[string]any{"ts": float64(time.Now().Unix()), "uid": "Cfull", "xid": 1234, "mac": "00:11:22:33:44:55", "client_chaddr": "00:11:22:33:44:55", "msg_types": "REQUEST", "capture_vlan": "997/997", "requested_addr": "10.161.128.11", "vendor_class": "MSFT 5.0", "requested_options": "1,3,6"})
	line := string(raw) + "\n"
	if err := os.WriteFile(path, []byte(line+line+"partial"), 0600); err != nil {
		t.Fatal(err)
	}
	return path, line
}
func TestDHCPOriginalSnapshotAndHashVerification(t *testing.T) {
	path, line := messageReplayFixture(t)
	m, err := snapshotDHCPMessages(path, "campus-204", "enp3s0f0", "10.0.0.0/8", 0, replayTestScope())
	if err != nil || len(m.Records) != 2 || m.NextOffset != int64(2*len(line)) || m.SnapshotSize != int64(2*len(line)+7) {
		t.Fatalf("snapshot lost source boundary: %+v %v", m, err)
	}
	e, reason, err := readDHCPMessage(m, m.Records[0])
	if err != nil || reason != "" || e.Subject["ip"] != nil || e.Subject["mac"] != "00:11:22:33:44:55" || e.Payload["uid"] != "Cfull" || e.Payload["dhcp_capture_vlan"] != "997/997" || e.RawRef["original_file_id"] != m.FileID {
		t.Fatalf("original replay changed scope or binding: %+v %s %v", e, reason, err)
	}
	page, err := snapshotDHCPMessages(path, "campus-204", "enp3s0f0", "10.0.0.0/8", int64(len(line)), replayTestScope())
	if err != nil || len(page.Records) != 1 || page.NextOffset != m.NextOffset {
		t.Fatalf("resume skipped or duplicated record: %+v %v", page, err)
	}
	if _, err = snapshotDHCPMessages(path, "campus-204", "enp3s0f0", "10.0.0.0/8", 1, replayTestScope()); err == nil {
		t.Fatal("mid-record offset accepted")
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("-tail\n")
	f.Close()
	if _, _, err = readDHCPMessage(m, m.Records[0]); err != nil {
		t.Fatalf("append invalidated a frozen prefix: %v", err)
	}
	f, _ = os.OpenFile(path, os.O_WRONLY, 0600)
	f.WriteAt([]byte("X"), 0)
	f.Close()
	if _, _, err = readDHCPMessage(m, m.Records[0]); err == nil {
		t.Fatal("changed original accepted")
	}
}
func TestDHCPOriginalRejectsReplacementAndHeaderChange(t *testing.T) {
	for _, variant := range []string{"replace", "header", "truncate"} {
		t.Run(variant, func(t *testing.T) {
			path, line := messageReplayFixture(t)
			if variant == "header" {
				line = "#separator \\x09\n" + line
				os.WriteFile(path, []byte(line), 0600)
			}
			m, err := snapshotDHCPMessages(path, "campus-204", "enp3s0f0", "10.0.0.0/8", 0, replayTestScope())
			if err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "replace":
				os.Rename(path, path+".original")
				os.WriteFile(path, []byte(line), 0600)
			case "truncate":
				os.Truncate(path, 1)
			case "header":
				f, _ := os.OpenFile(path, os.O_WRONLY, 0600)
				f.WriteAt([]byte("X"), 1)
				f.Close()
			}
			if _, _, err = readDHCPMessage(m, m.Records[0]); err == nil {
				t.Fatalf("%s source accepted", variant)
			}
		})
	}
}
func TestDHCPOriginalSnapshotByteAndRecordBounds(t *testing.T) {
	path, line := messageReplayFixture(t)
	os.WriteFile(path, []byte(strings.Repeat(line, 6000)), 0600)
	m, err := snapshotDHCPMessages(path, "campus-204", "enp3s0f0", "10.0.0.0/8", 0, replayTestScope())
	if err != nil || len(m.Records) > 5000 || m.NextOffset > 2<<20 || m.NextOffset >= m.SnapshotSize {
		t.Fatalf("page not bounded: %d %d %d %v", len(m.Records), m.NextOffset, m.SnapshotSize, err)
	}
	if len(m.Records) == 0 {
		t.Fatal("empty bounded page")
	}
	r := m.Records[0]
	r.SHA256 = strings.Repeat("0", 64)
	if _, _, err = readDHCPMessage(m, r); err == nil {
		t.Fatal("changed record proof accepted")
	}
}

func replayTestScope() *normalized.CaptureScope {
	return &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "campus-204", CollectorInstanceID: "fixture", CampusID: "campus-204", AccessDomain: "enp3s0f0", InterfaceName: "enp3s0f0", ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}
}

func TestDHCPOriginalRejectsMidFileSchema(t *testing.T) {
	path, line := messageReplayFixture(t)
	os.WriteFile(path, []byte(line+"#fields\tts\tmac\n"+line), 0600)
	if _, err := snapshotDHCPMessages(path, "campus-204", "enp3s0f0", "10.0.0.0/8", 0, replayTestScope()); err == nil {
		t.Fatal("mid-file schema silently ignored")
	}
}
func TestDHCPOriginalCLIEntrypoints(t *testing.T) {
	for _, mode := range []string{"snapshot-dhcp-messages", "apply-dhcp-messages"} {
		t.Run(mode, func(t *testing.T) {
			oldFlags, oldArgs := flag.CommandLine, os.Args
			t.Cleanup(func() { flag.CommandLine = oldFlags; os.Args = oldArgs })
			flag.CommandLine = flag.NewFlagSet("repair", flag.ContinueOnError)
			path, _ := messageReplayFixture(t)
			scopePath := filepath.Join(t.TempDir(), "scope.json")
			raw, _ := json.Marshal(replayTestScope())
			os.WriteFile(scopePath, raw, 0600)
			manifest := filepath.Join(t.TempDir(), "manifest.json")
			os.Args = []string{"repair", "--mode", mode, "--manifest", manifest, "--original-file", path, "--sensor", "campus-204", "--interface", "enp3s0f0", "--cidrs", "10.0.0.0/8", "--scope-file", scopePath}
			t.Setenv("PROXY_SENTINEL_POSTGRES_DSN", "")
			err := run(context.Background())
			if mode == "snapshot-dhcp-messages" {
				if err != nil {
					t.Fatal(err)
				}
				var m dhcpMessageManifest
				if err = readRepairJSON(manifest, &m); err != nil || len(m.Records) != 2 {
					t.Fatalf("CLI did not snapshot: %+v %v", m, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "PROXY_SENTINEL_POSTGRES_DSN") {
				t.Fatalf("apply mode not reachable: %v", err)
			}
		})
	}
}
