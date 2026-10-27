package discovery

import "strings"

// streamRecognitionFields keeps only current, self-reported product fields.
// Each value is bounded; the original normalized event remains authoritative.
func streamRecognitionFields(o Observation) map[string]string {
	fields := map[string]string{}
	add := func(field, value string) {
		value = strings.TrimSpace(value)
		if value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n") && len(fields) < 12 {
			fields[field] = value
		}
	}
	p := o.Evidence.Payload
	switch o.Origin {
	case "dhcp", "dhcpv6":
		add("hostname", firstText(str(p, "hostname"), o.Name))
		add("dhcp_vendor_class", str(p, "vendor_class"))
		add("dhcp_requested_options", firstText(str(p, "requested_options"), str(p, "parameter_request_list")))
	case "lldp":
		add("lldp_system_name", firstText(str(p, "system_name"), o.Name))
		add("lldp_system_description", str(p, "system_description"))
	case "cdp":
		add("cdp_device_id", firstText(str(p, "device_id"), o.Name))
		add("cdp_platform", str(p, "platform"))
	case "dns_sd":
		add("dns_sd_model", o.ModelName)
		add("service_type", str(p, "service_type"))
	case "ssdp":
		add("ssdp_model", o.ModelName)
		add("ssdp_manufacturer", o.Manufacturer)
		add("service_type", str(p, "service_type"))
	case "snmp":
		add("snmp_model", o.ModelName)
		add("snmp_sysoid", str(p, "system_object_id"))
		add("snmp_sysdescr", str(p, "system_description"))
	case "ipp":
		add("printer_make_and_model", firstText(str(p, "printer_make_and_model"), o.ModelName))
	case "onvif":
		add("onvif_model", o.ModelName)
		add("onvif_manufacturer", o.Manufacturer)
	case "mqtt":
		add("mqtt_model", o.ModelName)
	case "coap":
		add("coap_device_type", firstText(str(p, "device_type"), o.ModelName))
	case "bacnet":
		add("bacnet_model", o.ModelName)
	case "http":
		if str(p, "attribution_side") != "server" {
			break
		}
		add("http_server", str(p, "server"))
		add("http_title", str(p, "title"))
	case "tls":
		if str(p, "attribution_side") != "server" {
			break
		}
		add("tls_subject", firstText(str(p, "certificate_subject"), str(p, "subject")))
		add("tls_issuer", firstText(str(p, "certificate_issuer"), str(p, "issuer")))
		add("tls_san", firstText(str(p, "certificate_san"), str(p, "san")))
	case "ws_discovery":
		// WS-Discovery currently has no reviewed product field mapping.
	case "rtsp":
		// RTSP banner recognition requires a reviewed server-side parser.
	}
	return fields
}
