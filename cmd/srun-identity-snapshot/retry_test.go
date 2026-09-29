package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"proxy-sentinel/internal/legacy4k"
	"testing"
	"time"
)

func TestSnapshotRetryHelper(t *testing.T) {
	if os.Getenv("SENTINEL_SNAPSHOT_RETRY_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("snapshot-helper", flag.ExitOnError)
	if run() != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
func TestRetainedInventoryRetriesWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "pending.json")
	password := filepath.Join(dir, "secret")
	if err := os.WriteFile(password, []byte("test-only"), 0600); err != nil {
		t.Fatal(err)
	}
	inventory := &legacy4k.OnlineInventory{InstanceID: "redis-epoch", ObservedAt: time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond), Rows: []map[string]string{{"rad_online_id": "session", "user_name": "test", "ip": "192.0.2.1"}}}
	if err := writePending(state, inventory); err != nil {
		t.Fatal(err)
	}
	requests := make(chan []byte, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- body
		if len(requests) == 1 {
			w.WriteHeader(503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "completed", "snapshot_id": r.Header.Get("Idempotency-Key"), "session_count": 1})
	}))
	defer server.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSnapshotRetryHelper$", "--", "--redis-addr", "127.0.0.1:1", "--redis-password-file", password, "--endpoint", server.URL, "--token-file", password, "--state-file", state, "--source", "test", "--sensor-id", "lab", "--campus-id", "campus", "--access-domain", "nas", "--interval", "60")
	cmd.Env = append(os.Environ(), "SENTINEL_SNAPSHOT_RETRY_HELPER=1")
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() }()
	deadline := time.Now().Add(15 * time.Second)
	// Keep both requests queued so the handler deterministically fails only the first.
	for len(requests) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(requests) != 2 {
		t.Fatal("retained inventory was not resent after HTTP failure")
	}
	first, second := <-requests, <-requests
	if !bytes.Equal(first, second) {
		t.Fatal("retry changed pending inventory")
	}
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(state)
		if string(raw) == "null" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("acknowledged pending inventory not cleared")
}
