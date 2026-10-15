package zeek

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

// The dedicated Zeek stream carries candidate scope and response ownership;
// generic HTTP logs cannot assign a responder product to the requesting PC.
func iotMetadataEvent(raw []byte, fields map[string]string, line int, opts Options) (normalized.Event, error) {
	ip := fields["ip"]
	kind := fields["protocol"]
	timestamp := normalizeTimestamp(fields["ts"])
	if !discovery.IsPrivateDiscoveryAddress(ip) || fields["domain"] == "" || fields["interface_name"] == "" || timestamp == "" || fields["parser_version"] != "iot-metadata-v2" {
		return normalized.Event{}, fmt.Errorf("missing scoped metadata ownership")
	}
	metadata := fields["metadata"]
	if len(metadata) > 32768 {
		return normalized.Event{}, fmt.Errorf("metadata budget")
	}
	p := map[string]any{"origin": kind, "is_response": true, "ttl": 3600}
	switch kind {
	case "mqtt":
		var e error
		p, e = discovery.ParseMQTTDiscovery("homeassistant/sensor/device/config", []byte(metadata), true)
		if e != nil {
			return normalized.Event{}, e
		}
	case "ipp":
		b, e := base64.StdEncoding.DecodeString(metadata)
		if e != nil {
			return normalized.Event{}, e
		}
		p, e = discovery.ParseIPPAttributes(b)
		if e != nil {
			return normalized.Event{}, e
		}
	case "http", "rtsp":
		if len(metadata) > 512 {
			return normalized.Event{}, fmt.Errorf("header budget")
		}
		p["server"] = metadata
	case "tls":
		if len(metadata) > 128 {
			return normalized.Event{}, fmt.Errorf("TLS metadata budget")
		}
		p["version"] = metadata
	default:
		return normalized.Event{}, fmt.Errorf("unsupported TCP metadata protocol")
	}
	// Ensure the parser never forwards raw payloads or credentials.
	if _, e := json.Marshal(p); e != nil {
		return normalized.Event{}, e
	}
	return normalized.Event{SchemaVersion: "v1", EventID: eventID(raw, line), Source: "zeek", SourceEventType: kind, Type: "discovery", Timestamp: timestamp, Observer: map[string]any{"sensor_id": opts.SensorID, "source_id": "zeek-iot:" + opts.SensorID, "interface": fields["interface_name"]}, Subject: map[string]any{"ip": ip, "site": fields["site"], "domain": fields["domain"], "vlan": fields["vlan"]}, Payload: p, Confidence: 0.5}, nil
}
