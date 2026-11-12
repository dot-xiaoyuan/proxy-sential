package zeek

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"proxy-sentinel/internal/normalized"
)

// Zeek TSV escapes backslashes and control bytes before writing strings. Decode
// one logging layer only; JSON log values are already decoded by encoding/json.
func unescapeIdentityTSV(value string) string {
	var out strings.Builder
	for at := 0; at < len(value); at++ {
		if value[at] == '\\' && at+1 < len(value) {
			if value[at+1] == '\\' {
				out.WriteByte('\\')
				at++
				continue
			}
			if value[at+1] == 'x' && at+3 < len(value) {
				if v, err := strconv.ParseUint(value[at+2:at+4], 16, 8); err == nil {
					out.WriteByte(byte(v))
					at += 3
					continue
				}
			}
		}
		out.WriteByte(value[at])
	}
	return out.String()
}

// These are response value allowlists, not SNMP queries. Keep in sync with
// assets/zeek/snmp-device-signals.zeek. Never retain arbitrary management OIDs.
func identitySNMPOID(oid string) bool {
	switch oid {
	case "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.39165.1.1.0", "1.3.6.1.4.1.318.1.4.2.2.1.2.1", "1.3.6.1.4.1.21239.5.2.1.8.0":
		return true
	}
	for _, prefix := range []string{"1.3.6.1.2.1.47.1.1.1.1.2.", "1.3.6.1.2.1.47.1.1.1.1.12.", "1.3.6.1.2.1.47.1.1.1.1.13.", "1.3.6.1.2.1.43.5.1.1.16."} {
		if strings.HasPrefix(oid, prefix) && validOID(oid) {
			return true
		}
	}
	return false
}

func validOID(value string) bool {
	if len(value) > 128 || len(value) < 3 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 48 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return parts[0] == "0" || parts[0] == "1" || parts[0] == "2"
}

func identityText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' })
}

func strictBool(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "t", "true":
		return true, true
	case "f", "false":
		return false, true
	default:
		return false, false
	}
}

// Do not trust connection initiation or port numbers to identify the device.
// The parser must supply actual packet direction, checked against the tuple.
func passiveResponseEvent(raw []byte, fields map[string]string, line int, opts Options, payload map[string]any) (normalized.Event, error) {
	isOrig, ok := strictBool(fields["is_orig"])
	if !ok {
		return normalized.Event{}, fmt.Errorf("missing packet response direction")
	}
	source, dest := fields["source_h"], fields["destination_h"]
	orig, resp := fields["id.orig_h"], fields["id.resp_h"]
	wantSource, wantDest := resp, orig
	wantSourcePort, wantDestPort := zeekPort(fields["id.resp_p"]), zeekPort(fields["id.orig_p"])
	if isOrig {
		wantSource, wantDest = orig, resp
		wantSourcePort, wantDestPort = zeekPort(fields["id.orig_p"]), zeekPort(fields["id.resp_p"])
	}
	src, e1 := netip.ParseAddr(source)
	dst, e2 := netip.ParseAddr(dest)
	if e1 != nil || e2 != nil || src.IsUnspecified() || src.IsMulticast() || dst.IsUnspecified() || source != wantSource || dest != wantDest || zeekPort(fields["source_p"]) != wantSourcePort || zeekPort(fields["destination_p"]) != wantDestPort || wantSourcePort == 0 || wantDestPort == 0 {
		return normalized.Event{}, fmt.Errorf("inconsistent passive response source")
	}
	timestamp := normalizeTimestamp(fields["ts"])
	if timestamp == "" {
		return normalized.Event{}, fmt.Errorf("missing response event time")
	}
	payload["origin"], payload["is_response"], payload["response_source_ip"] = opts.LogKind, true, source
	payload["peer_ip"] = dest
	proto := "udp"
	if opts.LogKind == "modbus" {
		proto = "tcp"
	}
	flow := map[string]any{"src_ip": source, "dst_ip": dest, "src_port": wantSourcePort, "dst_port": wantDestPort, "proto": proto, "direction": "response"}
	if uid := fields["uid"]; len(uid) > 0 && len(uid) <= 128 {
		flow["connection_id"] = uid
	}
	event := zeekNetworkEvent(raw, fields, line, opts, "discovery", opts.LogKind, timestamp, source, dest, flow, payload)
	// The observed Ethernet source may be a router. The projection must resolve
	// this IP at event time using a trusted, same-scope binding; never copy L2 here.
	event.Subject = map[string]any{"ip": src.Unmap().String()}
	for _, key := range []string{"vlan", "inner_vlan", "vrf"} {
		if value := fields[key]; len(value) > 0 && len(value) <= 64 {
			event.Subject[key] = value
			event.Payload[key] = value
		}
	}
	// The current shared identity contract has one VLAN dimension. Preserve a
	// stacked tag as evidence but do not merge QinQ endpoints by the outer tag.
	if fields["inner_vlan"] != "" {
		event.Payload["endpoint_identity_unverified"] = true
	}
	sum := sha256.Sum256(raw)
	event.RawRef["content_sha256"] = hex.EncodeToString(sum[:])
	event.Confidence = 0.6
	return event, nil
}

func snmpResponseEvent(raw []byte, fields map[string]string, line int, opts Options) (normalized.Event, error) {
	response, ok := strictBool(fields["is_response"])
	if !ok || !response || fields["parser_version"] != "snmp-device/v1" {
		return normalized.Event{}, fmt.Errorf("not a verified SNMP response stream")
	}
	descr, oid := fields["system_description"], strings.TrimPrefix(fields["system_object_id"], ".")
	if descr != "" && !identityText(descr, 2048) || oid != "" && !validOID(oid) {
		return normalized.Event{}, fmt.Errorf("invalid SNMP identity field")
	}
	var bindings map[string]string
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
		var row struct {
			Bindings json.RawMessage `json:"snmp_varbinds"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return normalized.Event{}, err
		}
		if len(row.Bindings) > 0 {
			if row.Bindings[0] == '"' {
				var value string
				if err := json.Unmarshal(row.Bindings, &value); err != nil {
					return normalized.Event{}, err
				}
				row.Bindings = []byte(value)
			}
			if err := json.Unmarshal(row.Bindings, &bindings); err != nil {
				return normalized.Event{}, fmt.Errorf("invalid SNMP varbinds: %w", err)
			}
		}
	} else if value := fields["snmp_varbinds"]; value != "" {
		if err := json.Unmarshal([]byte(value), &bindings); err != nil {
			return normalized.Event{}, fmt.Errorf("invalid SNMP varbinds: %w", err)
		}
	}
	if len(bindings) == 0 || len(bindings) > 32 {
		return normalized.Event{}, fmt.Errorf("SNMP varbind count budget")
	}
	filtered, total := map[string]string{}, 0
	for k, value := range bindings {
		k = strings.TrimPrefix(k, ".")
		if !identitySNMPOID(k) {
			continue
		}
		limit := 512
		if k == "1.3.6.1.2.1.1.1.0" {
			limit = 2048
		}
		if !identityText(value, limit) {
			return normalized.Event{}, fmt.Errorf("SNMP varbind value budget")
		}
		total += len(k) + len(value)
		if total > 8192 {
			return normalized.Event{}, fmt.Errorf("SNMP varbind byte budget")
		}
		filtered[k] = value
	}
	if value := filtered["1.3.6.1.2.1.1.1.0"]; value != "" {
		if descr != "" && descr != value {
			return normalized.Event{}, fmt.Errorf("conflicting SNMP description")
		}
		descr = value
	}
	if value := filtered["1.3.6.1.2.1.1.2.0"]; value != "" {
		value = strings.TrimPrefix(value, ".")
		if !validOID(value) || oid != "" && oid != value {
			return normalized.Event{}, fmt.Errorf("conflicting SNMP object ID")
		}
		oid = value
	}
	if len(filtered) == 0 {
		return normalized.Event{}, fmt.Errorf("no allowed SNMP identity values")
	}
	payload := map[string]any{"parser_version": "snmp-device/v1", "snmp_varbinds": filtered}
	if descr != "" {
		payload["system_description"] = descr
	}
	if oid != "" {
		payload["system_object_id"] = oid
	}
	if version := fields["version"]; version == "1" || version == "2c" || version == "3" {
		payload["version"] = version
	}
	event, err := passiveResponseEvent(raw, fields, line, opts, payload)
	if err == nil {
		event.RawRef["log"] = "snmp_device"
	}
	return event, err
}

func industrialResponseEvent(raw []byte, fields map[string]string, line int, opts Options) (normalized.Event, error) {
	payload := map[string]any{"endpoint_identity_unverified": true}
	if opts.LogKind == "bacnet" {
		service := fields["pdu_service"]
		if (service != "read-property-ack" && service != "read-property-multiple-ack") || fields["object_type"] != "device" {
			return normalized.Event{}, fmt.Errorf("not a BACnet device property response")
		}
		value := fields["value"]
		if !identityText(value, 512) {
			return normalized.Event{}, fmt.Errorf("BACnet property value budget")
		}
		device, err := strconv.ParseUint(fields["instance_number"], 10, 22)
		if err != nil {
			return normalized.Event{}, fmt.Errorf("invalid BACnet device instance")
		}
		payload["bacnet_device_id"], payload["bacnet_property"], payload["parser_version"] = strconv.FormatUint(device, 10), fields["property"], "icsnpp-bacnet/72d1572ec170"
		switch fields["property"] {
		case "model-name":
			payload["product_model"] = value
		case "vendor-name":
			payload["manufacturer"] = value
		case "vendor-identifier":
			vendor, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return normalized.Event{}, err
			}
			payload["bacnet_vendor_id"] = strconv.FormatUint(vendor, 10)
		case "object-name":
			payload["bacnet_object_name"] = value
		default:
			return normalized.Event{}, fmt.Errorf("unselected BACnet property")
		}
	} else {
		if fields["request_response"] != "RESPONSE" || fields["mei_type"] != "READ-DEVICE-IDENTIFICATION" {
			return normalized.Event{}, fmt.Errorf("not a Modbus identification response")
		}
		value := fields["object_value"]
		if !identityText(value, 512) {
			return normalized.Event{}, fmt.Errorf("Modbus identity value budget")
		}
		unit, err := strconv.ParseUint(fields["unit"], 10, 8)
		if err != nil {
			return normalized.Event{}, fmt.Errorf("invalid Modbus unit")
		}
		payload["modbus_unit_id"], payload["parser_version"] = strconv.FormatUint(unit, 10), "icsnpp-modbus/6dd3dab173169"
		switch strings.ToLower(fields["object_id_code"]) {
		case "0x00":
			payload["modbus_vendor_name"], payload["manufacturer"] = value, value
		case "0x01":
			payload["modbus_product_code"] = value
		case "0x02":
			payload["modbus_revision"] = value
		case "0x04":
			payload["modbus_product_name"] = value
		case "0x05":
			payload["product_model"] = value
		default:
			return normalized.Event{}, fmt.Errorf("unselected Modbus identity object")
		}
	}
	event, err := passiveResponseEvent(raw, fields, line, opts, payload)
	if err == nil {
		if opts.LogKind == "bacnet" {
			event.RawRef["log"] = "bacnet_property"
		} else {
			event.RawRef["log"] = "modbus_read_device_identification"
		}
	}
	return event, err
}
