package discovery

// DeviceTypes is the display/filter catalogue for the complete discovery
// ledger. IoTTypes remains the narrower service classification rule catalogue.
var DeviceTypes = func() []IoTType {
	items := append([]IoTType(nil), IoTTypes...)
	return append(items,
		IoTType{"environment_monitor", "动环设备", "iot"},
		IoTType{"ups", "UPS", "iot"},
		IoTType{"pdu", "PDU", "iot"},
		IoTType{"access_point", "无线接入点", "network"},
		IoTType{"router", "路由器", "network"},
		IoTType{"switch", "交换机", "network"},
		IoTType{"gateway", "网关", "network"},
		IoTType{"firewall", "防火墙", "network"},
		IoTType{"desktop", "桌面终端", "desktop"},
		IoTType{"computer", "计算机", "desktop"},
		IoTType{"workstation", "工作站", "desktop"},
		IoTType{"laptop", "笔记本电脑", "desktop"},
		IoTType{"mobile", "手机", "mobile"},
		IoTType{"phone", "电话终端", "mobile"},
		IoTType{"smartphone", "智能手机", "mobile"},
		IoTType{"tablet", "平板设备", "tablet"},
		IoTType{"server", "服务器", "server"},
		IoTType{"media_device", "电视/媒体设备", "media"},
		IoTType{"iot", "物联网设备", "iot"},
		IoTType{"virtual_machine", "虚拟终端", "virtual"},
	)
}()
