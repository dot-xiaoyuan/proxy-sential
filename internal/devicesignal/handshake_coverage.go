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

// Diagnostics are serialized once per heartbeat. Per-device coverage proofs
// consumed by policy retain their original shape.
type captureCoverageDocument struct {
	sharedaccess.CoverageV2
	TLSReassembly  *helloReassemblyStats   `json:"priority_tls_reassembly,omitempty"`
	IEEE1905       *ieee1905CaptureStats   `json:"ieee1905,omitempty"`
	RouterSampling *routerSamplingCoverage `json:"authenticated_router_sampling,omitempty"`
}

func writeCaptureCoverage(path, sensor, iface, instance, source string, scope *normalized.CaptureScope, coverage sharedaccess.CoverageV2) error {
	return writeCaptureCoverageDocument(path, sensor, iface, instance, source, scope, captureCoverageDocument{CoverageV2: coverage})
}

func writeCaptureCoverageDocument(path, sensor, iface, instance, source string, scope *normalized.CaptureScope, document captureCoverageDocument) error {
	sum := sha256.Sum256([]byte(source + "/" + sensor + "/" + instance + "/" + document.From.Format(time.RFC3339Nano)))
	event := scope.Apply(normalized.Event{SchemaVersion: "v1", EventID: "coverage-" + hex.EncodeToString(sum[:16]), Source: source, SourceEventType: "capture_coverage", Type: "device", Timestamp: document.To.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor, "interface": iface, "collector_instance_id": instance}, Subject: map[string]any{}, Payload: map[string]any{"capture_coverage": document}})
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
