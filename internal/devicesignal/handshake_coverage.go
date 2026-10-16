package devicesignal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
	"time"
)

func writeHandshakeCoverage(path, sensor, iface, instance string, scope *normalized.CaptureScope, coverage sharedaccess.CoverageV2) error {
	return writeCaptureCoverage(path, sensor, iface, instance, "handshake-sidecar", scope, coverage)
}

func writeCaptureCoverage(path, sensor, iface, instance, source string, scope *normalized.CaptureScope, coverage sharedaccess.CoverageV2) error {
	sum := sha256.Sum256([]byte(source + "/" + sensor + "/" + instance + "/" + coverage.From.Format(time.RFC3339Nano)))
	event := scope.Apply(normalized.Event{SchemaVersion: "v1", EventID: "coverage-" + hex.EncodeToString(sum[:16]), Source: source, SourceEventType: "capture_coverage", Type: "device", Timestamp: coverage.To.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor, "interface": iface, "collector_instance_id": instance}, Subject: map[string]any{}, Payload: map[string]any{"capture_coverage": coverage}})
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = json.NewEncoder(f).Encode(event); err != nil {
		return err
	}
	return f.Sync()
}
