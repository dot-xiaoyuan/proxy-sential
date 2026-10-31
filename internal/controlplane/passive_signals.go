package controlplane

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
)

// PassiveSignal is a non-authoritative identification clue derived from
// mirror traffic only. OS hints come from TTL stack behavior; DHCP fields come
// from the Zeek DHCP message log.
type PassiveSignal struct {
	IP              string `json:"ip,omitempty"`
	MAC             string `json:"mac,omitempty"`
	TTL             int    `json:"ttl,omitempty"`
	OSHint          string `json:"os_hint,omitempty"`
	DeviceHint      string `json:"device_hint,omitempty"`
	DHCPHostname    string `json:"dhcp_hostname,omitempty"`
	DHCPVendorClass string `json:"dhcp_vendor_class,omitempty"`
	DHCPOptions     string `json:"dhcp_options,omitempty"`
	DHCPVLAN        string `json:"dhcp_vlan,omitempty"`
}

func (s *Server) handleDiscoveryPassiveSignals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	ips := splitList(r.URL.Query().Get("ips"), 100)
	macs := splitList(r.URL.Query().Get("macs"), 100)
	wantedIPs := map[string]bool{}
	wantedMACs := map[string]bool{}
	for _, ip := range ips {
		wantedIPs[ip] = true
	}
	for _, mac := range macs {
		wantedMACs[strings.ToLower(mac)] = true
	}
	if len(wantedIPs) == 0 && len(wantedMACs) == 0 {
		writeJSON(w, 200, map[string]any{"items": []PassiveSignal{}})
		return
	}
	signals := map[string]*PassiveSignal{}
	add := func(signal *PassiveSignal) {
		if signal == nil {
			return
		}
		if signal.IP != "" && wantedIPs[signal.IP] {
			signals[signal.IP] = signal
		}
		if signal.MAC != "" && wantedMACs[strings.ToLower(signal.MAC)] {
			if signals[signal.MAC] == nil {
				signals[signal.MAC] = signal
			}
		}
	}
	readTTLSignals(passiveTTLPath(), add)
	readDHCPSignals(passiveDHCPPath(), add)
	items := make([]*PassiveSignal, 0, len(signals))
	for _, signal := range signals {
		items = append(items, signal)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].IP < items[j].IP })
	writeJSON(w, 200, map[string]any{"items": items})
}

func splitList(raw string, limit int) []string {
	out := []string{}
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

func passiveTTLPath() string {
	if path := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_TTL_SIGNAL_PATH")); path != "" {
		return path
	}
	return "/opt/proxy-sentinel/data/device-signals/ttl.jsonl"
}

func passiveDHCPPath() string {
	if path := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_DHCP_MESSAGE_PATH")); path != "" {
		return path
	}
	return "/opt/proxy-sentinel/data/zeek/logs/current/device_dhcp_message.log"
}

func readTTLSignals(path string, add func(*PassiveSignal)) {
	lines := tailJSONLines(path, 32<<20)
	for _, line := range lines {
		var event struct {
			SourceEventType string `json:"source_event_type"`
			Subject         struct {
				IP  string `json:"ip"`
				MAC string `json:"mac"`
			} `json:"subject"`
			Payload struct {
				TTL         int    `json:"ttl"`
				NeighborMAC string `json:"neighbor_mac"`
			} `json:"payload"`
		}
		if json.Unmarshal(line, &event) != nil || event.Subject.IP == "" || event.Payload.TTL <= 0 {
			continue
		}
		mac := event.Payload.NeighborMAC
		if mac == "" {
			mac = event.Subject.MAC
		}
		add(&PassiveSignal{IP: event.Subject.IP, MAC: mac, TTL: event.Payload.TTL, OSHint: ttlOSHint(event.Payload.TTL)})
	}
}

func readDHCPSignals(path string, add func(*PassiveSignal)) {
	lines := tailJSONLines(path, 16<<20)
	for _, line := range lines {
		var event struct {
			MAC              string `json:"mac"`
			RequestedAddr    string `json:"requested_addr"`
			HostName         string `json:"host_name"`
			VendorClass      string `json:"vendor_class"`
			RequestedOptions string `json:"requested_options"`
			CaptureVLAN      string `json:"capture_vlan"`
		}
		if json.Unmarshal(line, &event) != nil || (event.MAC == "" && event.RequestedAddr == "") {
			continue
		}
		signal := &PassiveSignal{
			IP:              event.RequestedAddr,
			MAC:             strings.ToLower(strings.TrimSpace(event.MAC)),
			DHCPHostname:    event.HostName,
			DHCPVendorClass: event.VendorClass,
			DHCPOptions:     event.RequestedOptions,
			DHCPVLAN:        event.CaptureVLAN,
		}
		if vendor := strings.ToLower(event.VendorClass); vendor != "" {
			for _, networkVendor := range []string{"ruijie", "h3c", "huawei", "cisco", "aruba", "juniper", "tp-link", "tplink", "zyxel"} {
				if strings.Contains(vendor, networkVendor) {
					signal.DeviceHint = "网络设备"
					break
				}
			}
		}
		add(signal)
	}
}

func ttlOSHint(ttl int) string {
	switch {
	case ttl <= 32:
		return "嵌入式/网络设备类"
	case ttl <= 64:
		return "Linux/Unix 类"
	case ttl <= 128:
		return "Windows/网络设备类"
	default:
		return "网络设备类"
	}
}

func tailJSONLines(path string, maxBytes int64) [][]byte {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		return nil
	}
	start := info.Size() - maxBytes
	if start < 0 {
		start = 0
	}
	if _, err = file.Seek(start, io.SeekStart); err != nil {
		return nil
	}
	scanner := bufio.NewScanner(io.LimitReader(file, maxBytes))
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	lines := make([][]byte, 0, 256)
	first := true
	for scanner.Scan() {
		line := scanner.Bytes()
		if first && start > 0 {
			first = false
			continue
		}
		first = false
		if len(line) == 0 {
			continue
		}
		lines = append(lines, append([]byte(nil), line...))
	}
	return lines
}
