package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/legacy4k"
)

func TestPendingInventoryDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "pending.json")
	in := &legacy4k.OnlineInventory{InstanceID: "epoch", ObservedAt: time.Now().UTC(), Rows: []map[string]string{{"rad_online_id": "1", "user_name": "test"}}}
	if err := writePending(path, in); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var restored *legacy4k.OnlineInventory
	if err = json.Unmarshal(raw, &restored); err != nil || restored.InstanceID != in.InstanceID || !restored.ObservedAt.Equal(in.ObservedAt) {
		t.Fatal(restored, err)
	}
	stat, _ := os.Stat(path)
	if stat.Mode().Perm() != 0600 {
		t.Fatal("pending contains private identity data", stat.Mode())
	}
	if err = writePending(path, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != "null" {
		t.Fatal("committed pending not cleared")
	}
	if err = writePending(filepath.Join(path, "invalid"), in); err == nil {
		t.Fatal("write failure ignored")
	}
}
