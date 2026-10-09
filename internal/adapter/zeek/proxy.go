package zeek

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"strconv"
	"strings"
	"time"
)

func proxyEvent(raw []byte, f map[string]string, opts Options) (normalized.Event, error) {
	ts := proxyTimestamp(f["ts"])
	if ts == "" || f["id.orig_h"] == "" {
		return normalized.Event{}, fmt.Errorf("missing proxy timestamp or origin")
	}
	sum := sha256.Sum256(raw)
	payload := map[string]any{"protocol": f["protocol"], "transaction_id": f["transaction_id"]}
	for _, key := range []string{"method", "status", "version", "command", "reply"} {
		if f[key] != "" && f[key] != "-" {
			payload[key] = f[key]
		}
	}
	for _, key := range []string{"request_at", "response_at"} {
		if value := proxyTimestamp(f[key]); value != "" {
			payload[key] = value
		}
	}
	e := normalized.Event{SchemaVersion: "v1", EventID: "zeek-proxy-" + hex.EncodeToString(sum[:]), Source: "zeek", SourceEventType: "proxy_transactions", Type: "proxy_transaction", Timestamp: ts, Observer: map[string]any{"sensor_id": opts.SensorID, "collector_instance_id": opts.CollectorInstanceID}, Subject: map[string]any{"ip": f["id.orig_h"]}, Flow: map[string]any{"src_ip": f["id.orig_h"], "dst_ip": f["id.resp_h"], "connection_id": normalized.ConnectionID(opts.SensorID, "zeek", opts.CollectorInstanceID, f["uid"])}, Payload: payload, RawRef: map[string]any{"backend": "zeek", "uid": f["uid"]}, Confidence: 1}
	if opts.ProxyProducer != nil {
		if err := proxyprotocol.Sign(&e, *opts.ProxyProducer); err != nil {
			return normalized.Event{}, err
		}
	}
	return e, nil
}

func proxyTimestamp(value string) string {
	if value == "" || value == "-" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	}
	parts := strings.SplitN(value, ".", 2)
	sec, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return ""
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	fraction += "000000"
	micros, err := strconv.ParseInt(fraction[:6], 10, 64)
	if err != nil {
		return ""
	}
	return time.Unix(sec, micros*1000).UTC().Format(time.RFC3339Nano)
}
