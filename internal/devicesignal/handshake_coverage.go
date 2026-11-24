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
	return writeCaptureCoverageDocument(path, sensor, iface, instance, source, scope, coverage, nil)
}

func writeCaptureCoverageDocument(path, sensor, iface, instance, source string, scope *normalized.CaptureScope, coverage sharedaccess.CoverageV2, stats *ieee1905CaptureStats) error {
	sum := sha256.Sum256([]byte(source + "/" + sensor + "/" + instance + "/" + coverage.From.Format(time.RFC3339Nano)))
	// Input diagnostics live only on the capture heartbeat. The coverage proof
	// attached to a device record and used by policy keeps its original shape.
	document := struct {
		sharedaccess.CoverageV2
		IEEE1905 *ieee1905CaptureStats `json:"ieee1905,omitempty"`
	}{coverage, stats}
	event := scope.Apply(normalized.Event{SchemaVersion: "v1", EventID: "coverage-" + hex.EncodeToString(sum[:16]), Source: source, SourceEventType: "capture_coverage", Type: "device", Timestamp: coverage.To.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor, "interface": iface, "collector_instance_id": instance}, Subject: map[string]any{}, Payload: map[string]any{"capture_coverage": document}})
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
