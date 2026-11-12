package controlplane

import "os"

// Shadow generation must not switch any read path. Both the discovery reader
// and census/export reader use this one gate; 184 keeps its existing default.
func discoveryHardwareReadEnabled() bool {
	return os.Getenv("PROXY_SENTINEL_HARDWARE_V2") == "true"
}

func discoveryHardwareReadPathConflict() bool {
	return discoveryHardwareReadEnabled() && (discoveryStreamCurrentReadEnabled() || os.Getenv("PROXY_SENTINEL_DISCOVERY_V2") == "true" || os.Getenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ") == "true")
}
