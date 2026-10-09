package realtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func rotationDNS(ip string) string {
	return fmt.Sprintf(`{"timestamp":"2026-07-22T10:00:00Z","event_type":"dns","src_ip":%q,"dest_ip":"1.1.1.1","proto":"UDP","dns":{"rrname":"example.test"}}`+"\n", ip)
}

func TestRotationDrainsMatchingArchiveBeforeReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	first, pending, current := rotationDNS("10.0.0.1"), rotationDNS("10.0.0.2"), rotationDNS("10.0.0.3")
	if err := os.WriteFile(path, []byte(first+pending), 0600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	opts := Options{SensorID: "rotation", MaxBatchBytes: int64(len(first)), StoreTimeout: time.Second}
	source := Source{Kind: "suricata", Path: path}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	oldID := backend.checkpoint.FileID
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(current), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 2 || backend.events[1].Subject["ip"] != "10.0.0.2" || backend.checkpoint.FileID != oldID {
		t.Fatalf("unread archive skipped: events=%+v checkpoint=%+v", backend.events, backend.checkpoint)
	}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 3 || backend.events[2].Subject["ip"] != "10.0.0.3" || backend.checkpoint.FileID == oldID {
		t.Fatalf("replacement not consumed after archive: %+v", backend)
	}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 3 {
		t.Fatalf("archive replayed after switching: %d", len(backend.events))
	}
}

func TestRotationArchiveRetryKeepsDurableIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	first, pending, current := rotationDNS("10.0.0.1"), rotationDNS("10.0.0.2"), rotationDNS("10.0.0.3")
	if err := os.WriteFile(path, []byte(first+pending), 0600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	opts := Options{SensorID: "rotation", MaxBatchBytes: int64(len(first)), StoreTimeout: time.Second}
	source := Source{Kind: "suricata", Path: path}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	saved := backend.checkpoint
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	// The rename/create gap must still allow draining the retained descriptor.
	backend.writeRunErr = fmt.Errorf("storage unavailable")
	if err := ProcessOnce(context.Background(), backend, opts, source); err == nil {
		t.Fatal("expected failure")
	}
	if backend.checkpoint != saved {
		t.Fatalf("failed archive batch advanced checkpoint: %+v", backend.checkpoint)
	}
	failedID := backend.batches[len(backend.batches)-1].BatchID
	if err := os.WriteFile(path, []byte(current), 0600); err != nil {
		t.Fatal(err)
	}
	backend.writeRunErr = nil
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if backend.batches[len(backend.batches)-1].BatchID != failedID {
		t.Fatal("archive retry changed batch ID")
	}
	if backend.diagnostics[len(backend.diagnostics)-1].Details["archive_draining"] != true {
		t.Fatal("archive evidence missing")
	}
	if backend.events[len(backend.events)-1].Subject["ip"] != "10.0.0.2" {
		t.Fatal("retry read replacement")
	}
}

func TestRotationIncompleteTailDoesNotAdvanceToReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	first, pending := rotationDNS("10.0.0.1"), rotationDNS("10.0.0.2")
	if err := os.WriteFile(path, []byte(first+pending[:len(pending)-1]), 0600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	opts := Options{SensorID: "rotation", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}
	source := Source{Kind: "suricata", Path: path}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	saved := backend.checkpoint
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(rotationDNS("10.0.0.3")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ProcessOnce(context.Background(), backend, opts, source); err == nil {
		t.Fatal("incomplete archive should be surfaced")
	}
	if backend.checkpoint != saved || len(backend.events) != 1 {
		t.Fatal("incomplete archive skipped")
	}
	f, err := os.OpenFile(path+".1", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 2 || backend.events[1].Subject["ip"] != "10.0.0.2" {
		t.Fatal("completed archive not recovered")
	}
}

func TestZeekRotatedChunkUsesMatchingDescriptorHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp.log")
	header := "#separator \\x09\n#fields\tts\tclient_addr\tserver_addr\tmac\n"
	first := "1784714400\t10.0.0.1\t10.0.0.254\taa:bb:cc:dd:ee:01\n"
	pending := "1784714401\t10.0.0.2\t10.0.0.254\taa:bb:cc:dd:ee:02\n"
	if err := os.WriteFile(path, []byte(header+first+pending), 0600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	opts := Options{SensorID: "rotation", MaxBatchBytes: int64(len(header + first)), StoreTimeout: time.Second}
	source := Source{Kind: "zeek-dhcp", Path: path}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	replacement := "#separator \\x09\n#fields\tts\tserver_addr\tclient_addr\tmac\n1784714402\t10.0.0.254\t10.0.0.3\taa:bb:cc:dd:ee:03\n"
	if err := os.WriteFile(path, []byte(replacement), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 2 || backend.events[1].Subject["ip"] != "10.0.0.2" {
		t.Fatalf("archive parsed with replacement header: %+v", backend.events)
	}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 3 || backend.events[2].Subject["ip"] != "10.0.0.3" {
		t.Fatalf("replacement layout incorrect: %+v", backend.events)
	}
}

func TestZeekSNMPRotationKeepsSanitizedIdentityCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snmp.log")
	header := "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tdisplay_string\n"
	first := "1784714400\tC1\t222.204.7.64\t40001/udp\t10.1.0.30\t161/udp\t2c\tCisco ISR4331\n"
	pending := "1784714401\tC2\t222.204.7.64\t40002/udp\t10.1.0.31\t161/udp\t2c\tHuawei AR6140\n"
	if err := os.WriteFile(path, []byte(header+first+pending), 0600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	opts := Options{SensorID: "rotation", MaxBatchBytes: int64(len(header + first)), StoreTimeout: time.Second}
	source := Source{Kind: "zeek-snmp", Path: path}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	checkpoint := backend.checkpoint
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	replacement := "#separator \\x09\n#fields\tts\tuid\tid.resp_h\tid.resp_p\tid.orig_h\tid.orig_p\tversion\tdisplay_string\n1784714402\tC3\t10.1.0.32\t161/udp\t222.204.7.64\t40003/udp\t3\tJuniper MX480\n"
	if err := os.WriteFile(path, []byte(replacement), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 2 || backend.events[1].Subject["ip"] != "10.1.0.31" || backend.checkpoint.FileID != checkpoint.FileID {
		t.Fatalf("SNMP archive checkpoint skipped identity: events=%+v checkpoint=%+v", backend.events, backend.checkpoint)
	}
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 3 || backend.events[2].Subject["ip"] != "10.1.0.32" || backend.checkpoint.FileID == checkpoint.FileID {
		t.Fatalf("SNMP replacement was not consumed: events=%+v checkpoint=%+v", backend.events, backend.checkpoint)
	}
}

func TestRotationLagIncludesUnreadArchiveAndReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte("first\npending\n"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id := fileIdentity(path, info)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := sourceLag(path, id, 6); got != 12 {
		t.Fatalf("lag lost old or new bytes: %d", got)
	}
	if got := sourceLag(path, id, 14); got != 4 {
		t.Fatalf("replacement backlog disappeared: %d", got)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := sourceLag(path, fileIdentity(path, info), 4); got != 0 {
		t.Fatalf("completed source replayed unrelated archive: %d", got)
	}
}
