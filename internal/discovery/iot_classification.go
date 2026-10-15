package discovery

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

const IoTRuleVersion = "iot-evidence-v2"
const PrivateDiscoveryCIDRs = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10"

type IoTType struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Category string `json:"category"`
}

var IoTTypes = []IoTType{
	{"printer", "打印机", "printer"}, {"scanner", "扫描仪", "printer"}, {"camera", "摄像机", "camera"}, {"recorder", "录像设备", "camera"},
	{"media_player", "媒体播放设备", "media"}, {"display", "显示设备", "media"}, {"access_control", "门禁设备", "access_control"},
	{"attendance", "考勤设备", "attendance"}, {"building_controller", "楼宇控制器", "building_controller"}, {"building_device", "楼宇设备", "building_controller"}, {"sensor", "传感设备", "sensor"}, {"iot_gateway", "智能网关", "iot_gateway"},
}

type IoTClassification struct {
	DeviceType  string   `json:"device_type"`
	Category    string   `json:"category"`
	Confidence  string   `json:"confidence"`
	Reason      string   `json:"reason"`
	RuleVersion string   `json:"rule_version"`
	Conflict    bool     `json:"conflict"`
	EvidenceIDs []string `json:"evidence_ids"`
}

func IsPrivateDiscoveryAddress(s string) bool {
	a, e := netip.ParseAddr(s)
	if e != nil {
		return false
	}
	a = a.Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast()
}
func iotCategory(kind string) string {
	for _, t := range IoTTypes {
		if t.ID == kind {
			return t.Category
		}
	}
	return ""
}

// Classification uses typed protocol declarations, never hostnames, OUI or ports.
func observationIoTType(o Observation) (string, string) {
	p := o.Evidence.Payload
	if o.Origin == "mqtt" && p["self_binding_verified"] != true {
		return "", ""
	}
	if o.Origin == "mqtt" && p["device_declaration"] == true && str(p, "product_type") == "sensor" && str(p, "product_model") != "" {
		return "sensor", "设备声明与当前地址绑定一致"
	}
	if p["product_verified"] == true {
		kind := str(p, "product_type")
		if iotCategory(kind) != "" && str(p, "product_model") != "" {
			return kind, "产品型号与设备类型规则匹配"
		}
	}
	service := strings.ToLower(str(p, "service_type"))
	txt := strings.ToLower(protocolText(p["txt"]))
	switch o.Origin {
	case "dns_sd":
		hasProduct := strings.Contains(txt, "product=") || strings.Contains(txt, "ty=") || strings.Contains(txt, "usb_mdl=")
		if hasProduct {
			switch service {
			case "_ipp._tcp", "_ipps._tcp", "_printer._tcp":
				return "printer", "打印服务与产品声明一致"
			case "_uscan._tcp", "_uscans._tcp", "_scanner._tcp":
				return "scanner", "扫描服务与产品声明一致"
			}
		}
		if strings.Contains(txt, "model=appletv") || strings.Contains(txt, "md=chromecast") {
			return "media_player", "服务携带专用媒体产品型号"
		}
	case "ws_discovery":
		if p["is_response"] != true {
			return "", ""
		}
		types := strings.ToLower(str(p, "types"))
		if strings.Contains(types, "networkvideotransmitter") {
			return "camera", "WS-Discovery 声明网络视频发送设备类"
		}
		if strings.Contains(types, "networkvideostorage") {
			return "recorder", "WS-Discovery 声明网络录像设备类"
		}
	case "snmp":
		if p["is_response"] == true && str(p, "hr_device_type") == "1.3.6.1.2.1.25.3.1.5" {
			return "printer", "SNMP 打印设备对象"
		}
	case "ipp":
		if p["is_response"] == true && str(p, "printer_make_and_model") != "" {
			return "printer", "IPP 返回打印机产品属性"
		}
	case "bacnet":
		if p["is_response"] == true && str(p, "object_type") == "device" && str(p, "device_identifier") != "" {
			return "building_device", "BACnet I-Am 声明楼宇设备对象"
		}
	case "coap":
		if p["is_response"] == true {
			switch str(p, "device_resource_type") {
			case "oic.d.sensor":
				return "sensor", "CoAP 设备资源声明传感设备类"
			case "oic.d.tv":
				return "display", "CoAP 设备资源声明显示设备类"
			case "oic.d.camera":
				return "camera", "CoAP 设备资源声明摄像设备类"
			case "oic.d.gateway":
				return "iot_gateway", "CoAP 设备资源声明网关类"
			}
		}
	case "ssdp", "onvif", "http", "tls", "mqtt":
		// Model rules are emitted by registered parsers/enrichers, not copied from
		// hostnames or arbitrary payload keys. Protocol evidence remains attached.
		if p["product_verified"] == true {
			kind := str(p, "product_type")
			if iotCategory(kind) != "" && str(p, "product_model") != "" {
				return kind, "协议产品型号与设备类规则匹配"
			}
		}
	}
	return "", ""
}
func ClassifyIoT(observations []Observation, now time.Time) IoTClassification {
	result := IoTClassification{RuleVersion: IoTRuleVersion, EvidenceIDs: []string{}}
	kinds := map[string]string{}
	excluded := false
	for _, o := range observations {
		if !o.Current(now) {
			continue
		}
		switch o.DeviceType {
		case "mobile", "phone", "desktop", "laptop", "computer", "server", "router", "switch", "access_point", "firewall":
			excluded = true
		}
		kind, reason := observationIoTType(o)
		if kind != "" {
			kinds[kind] = reason
			result.EvidenceIDs = append(result.EvidenceIDs, o.ID)
		}
	}
	if _, printing := kinds["printer"]; printing {
		delete(kinds, "scanner")
	}
	if len(kinds) > 1 || excluded && len(kinds) > 0 {
		result.Conflict = true
		result.Reason = "设备类型证据冲突"
		return result
	}
	if excluded {
		return result
	}
	for kind, reason := range kinds {
		result.DeviceType = kind
		result.Category = iotCategory(kind)
		result.Confidence = "strong"
		result.Reason = reason
	}
	sort.Strings(result.EvidenceIDs)
	return result
}

func protocolText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []string:
		return strings.Join(x, ";")
	case []any:
		parts := []string{}
		for _, v := range x {
			if s, ok := v.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ";")
	}
	return ""
}
