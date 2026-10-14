package discovery

// The IoT view requires a device's own service announcement. A DHCP lease,
// hostname or endpoint profile alone cannot establish an IoT device type.
func iotServiceCategory(item DeviceView) string {
	for _, o := range item.Observations {
		if o.Withdrawn || confidenceRank(o.Confidence) == 0 || (o.Confidence == "clue" && o.MAC == "") {
			continue
		}
		switch o.Origin {
		case "dns_sd", "ssdp", "ws_discovery":
			for _, capability := range o.Capabilities {
				switch capability {
				case "printing", "scanning":
					return "printer"
				case "network_video":
					return "camera"
				case "casting", "media_rendering":
					return "media"
				}
			}
		}
	}
	return ""
}
