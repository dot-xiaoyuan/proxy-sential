package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRTSPOriginalReplayPreservesOwnerAndProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rtsp_device.log")
	row, _ := json.Marshal(map[string]any{"ts": float64(time.Now().Unix()), "uid": "Crecorder", "src_h": "10.126.255.253", "src_p": 41234, "dst_h": "10.126.254.5", "dst_p": 554, "method": "DESCRIBE", "value": "HIKVISION player NVR V4.74.210", "direction": "client"})
	if err := os.WriteFile(path, append(row, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := snapshotOriginalProtocol(path, "campus-204", "enp3s0f0", "10.0.0.0/8", 0, replayTestScope(), "rtsp-device")
	if err != nil || len(m.Records) != 1 {
		t.Fatalf("snapshot: %+v %v", m, err)
	}
	e, reason, err := readDHCPMessage(m, m.Records[0])
	if err != nil || reason != "" || e.SourceEventType != "rtsp" || e.Subject["ip"] != "10.126.255.253" || e.Flow["direction"] != "client" || e.Payload["user_agent"] != "HIKVISION player NVR V4.74.210" || e.RawRef["original_file_id"] != m.FileID {
		t.Fatalf("source replay changed product owner: %+v %s %v", e, reason, err)
	}
	if e.Subject["mac"] != nil && e.Subject["mac"] != "" {
		t.Fatal("invented physical MAC")
	}
	if _, err := snapshotOriginalProtocol(path, "campus-204", "enp3s0f0", "10.0.0.0/8", 0, replayTestScope(), "conn"); err == nil {
		t.Fatal("unsupported protocol replay enabled")
	}
	m.LogKind = "conn"
	if _, _, err := readDHCPMessage(m, m.Records[0]); err == nil {
		t.Fatal("tampered protocol accepted")
	}
}
