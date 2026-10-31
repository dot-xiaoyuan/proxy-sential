package controlplane

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

// PassiveSignal is a non-authoritative identification clue derived from
// mirror traffic only. OS hints come from TTL stack behavior; DHCP fields come
// from the Zeek DHCP message log.
type PassiveSignal struct {
	SensorID            string              `json:"sensor_id,omitempty"`
	IP                  string              `json:"ip,omitempty"`
	MAC                 string              `json:"mac,omitempty"`
	TTL                 int                 `json:"ttl,omitempty"`
	OSHint              string              `json:"os_hint,omitempty"`
	DeviceHint          string              `json:"device_hint,omitempty"`
	DHCPHostname        string              `json:"dhcp_hostname,omitempty"`
	DHCPVendorClass     string              `json:"dhcp_vendor_class,omitempty"`
	DHCPOptions         string              `json:"dhcp_options,omitempty"`
	DHCPClientIDHWType  string              `json:"dhcp_client_id_hwtype,omitempty"`
	DHCPOption93Present bool                `json:"dhcp_option93_present,omitempty"`
	DHCPVLAN            string              `json:"dhcp_vlan,omitempty"`
	TTLVLAN             string              `json:"ttl_vlan,omitempty"`
	DHCPObservedAt      string              `json:"dhcp_observed_at,omitempty"`
	DHCPEvidenceID      string              `json:"dhcp_evidence_id,omitempty"`
	DHCPHistorical      bool                `json:"dhcp_historical,omitempty"`
	TTLObservedAt       string              `json:"ttl_observed_at,omitempty"`
	OSFamily            string              `json:"os_family,omitempty"`
	OSConfidence        string              `json:"os_confidence,omitempty"`
	OSEvidence          string              `json:"os_evidence,omitempty"`
	OSConflict          bool                `json:"os_conflict,omitempty"`
	ClientClues         []PassiveClientClue `json:"client_clues,omitempty"`
}

type passiveSignalFile struct {
	path     string
	size     int64
	modified time.Time
}

var passiveSignalSnapshot struct {
	sync.Mutex
	ttl, dhcp passiveSignalFile
	sensor    string
	items     []PassiveSignal
	checkedAt time.Time
}

func passiveFileState(path string) passiveSignalFile {
	state := passiveSignalFile{path: path}
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		state.size, state.modified = info.Size(), info.ModTime()
	}
	return state
}

// A changed log is read once for all list requests. The scanners below bound
// work to the recent tail; missing or rotated files invalidate this snapshot.
func cachedPassiveSignals() []PassiveSignal {
	passiveSignalSnapshot.Lock()
	defer passiveSignalSnapshot.Unlock()
	sensor := passiveLogSensorID()
	if passiveSignalSnapshot.items != nil && time.Since(passiveSignalSnapshot.checkedAt) < 15*time.Second && passiveSignalSnapshot.ttl.path == passiveTTLPath() && passiveSignalSnapshot.dhcp.path == passiveDHCPPath() && passiveSignalSnapshot.sensor == sensor {
		return passiveSignalSnapshot.items
	}
	passiveSignalSnapshot.checkedAt = time.Now()
	ttl, dhcp := passiveFileState(passiveTTLPath()), passiveFileState(passiveDHCPPath())
	if passiveSignalSnapshot.items != nil && ttl == passiveSignalSnapshot.ttl && dhcp == passiveSignalSnapshot.dhcp && passiveSignalSnapshot.sensor == sensor {
		return passiveSignalSnapshot.items
	}
	byKey := make(map[string]*PassiveSignal)
	add := func(signal *PassiveSignal) { mergePassiveSignal(byKey, signal) }
	readTTLSignals(ttl.path, add)
	readDHCPSignals(dhcp.path, sensor, add)
	items := make([]PassiveSignal, 0, len(byKey))
	for _, signal := range byKey {
		items = append(items, *signal)
	}
	passiveSignalSnapshot.ttl, passiveSignalSnapshot.dhcp, passiveSignalSnapshot.sensor, passiveSignalSnapshot.items = ttl, dhcp, sensor, items
	return items
}

func mergePassiveSignal(byKey map[string]*PassiveSignal, signal *PassiveSignal) {
	if signal == nil {
		return
	}
	key := passiveSignalKey(signal)
	if key == "" {
		return
	}
	current := byKey[key]
	if current == nil {
		current = &PassiveSignal{}
		byKey[key] = current
	}
	current.SensorID = signal.SensorID
	if signal.IP != "" {
		current.IP = signal.IP
	}
	if signal.MAC != "" {
		current.MAC = strings.ToLower(signal.MAC)
	}
	if signal.TTL > 0 {
		current.TTL, current.OSHint, current.TTLObservedAt = signal.TTL, signal.OSHint, signal.TTLObservedAt
	}
	newerDHCP := current.DHCPObservedAt == "" || signal.DHCPObservedAt >= current.DHCPObservedAt
	if signal.DHCPHostname != "" && newerDHCP {
		current.DHCPHostname = signal.DHCPHostname
	}
	if signal.DHCPVendorClass != "" && newerDHCP {
		current.DHCPVendorClass = signal.DHCPVendorClass
	}
	if signal.DHCPOptions != "" && newerDHCP {
		current.DHCPOptions = signal.DHCPOptions
	}
	if signal.DHCPClientIDHWType != "" && newerDHCP {
		current.DHCPClientIDHWType = signal.DHCPClientIDHWType
	}
	if signal.DHCPOption93Present {
		current.DHCPOption93Present = true
	}
	if signal.DHCPVLAN != "" {
		current.DHCPVLAN = signal.DHCPVLAN
	}
	if signal.TTLVLAN != "" {
		current.TTLVLAN = signal.TTLVLAN
	}
	if signal.DHCPObservedAt != "" && newerDHCP {
		current.DHCPObservedAt = signal.DHCPObservedAt
		current.DHCPEvidenceID = signal.DHCPEvidenceID
	}
	current.DHCPHistorical = current.DHCPHistorical || signal.DHCPHistorical
	if signal.DeviceHint != "" {
		current.DeviceHint = signal.DeviceHint
	}
	for _, clue := range signal.ClientClues {
		if len(current.ClientClues) >= 12 {
			break
		}
		duplicate := false
		for _, prior := range current.ClientClues {
			if prior.Kind == clue.Kind && prior.Value == clue.Value && prior.EvidenceID == clue.EvidenceID {
				duplicate = true
				break
			}
		}
		if !duplicate {
			current.ClientClues = append(current.ClientClues, clue)
		}
	}
	if signal.OSFamily != "" {
		if current.OSFamily != "" && current.OSFamily != signal.OSFamily {
			current.OSConflict = true
			current.OSEvidence += "；" + signal.OSEvidence
		}
		if !current.OSConflict {
			current.OSFamily, current.OSConfidence, current.OSEvidence = signal.OSFamily, signal.OSConfidence, signal.OSEvidence
		}
	}
	if current.DHCPHistorical && current.OSFamily != "" {
		current.OSConfidence = "weak"
	}
}

func passiveSignalKey(signal *PassiveSignal) string {
	if signal == nil || signal.IP == "" && signal.MAC == "" {
		return ""
	}
	vlan := signal.DHCPVLAN
	if vlan == "" {
		vlan = signal.TTLVLAN
	}
	key := signal.SensorID + "|ip:" + signal.IP + "|" + vlan
	if signal.MAC != "" {
		key = signal.SensorID + "|mac:" + strings.ToLower(signal.MAC) + "|" + vlan
	}
	return key
}

func (s *Server) handleDiscoveryPassiveSignals(w http.ResponseWriter, r *http.Request, repo discovery.Repository) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	ips := splitList(r.URL.Query().Get("ips"), 100)
	macs := splitList(r.URL.Query().Get("macs"), 100)
	sensors := splitList(r.URL.Query().Get("sensors"), 20)
	wantedIPs := map[string]bool{}
	wantedMACs := map[string]bool{}
	for _, ip := range ips {
		wantedIPs[ip] = true
	}
	for _, mac := range macs {
		wantedMACs[strings.ToLower(mac)] = true
	}
	if len(wantedIPs) == 0 && len(wantedMACs) == 0 {
		writeJSON(w, 200, map[string]any{"items": []PassiveSignal{}, "durable_status": "not_requested", "client_status": "not_requested"})
		return
	}
	byKey := make(map[string]*PassiveSignal)
	clientByKey := make(map[string]*PassiveSignal)
	response := map[string]any{"durable_status": "ready", "client_status": "not_requested"}
	if repo.DB != nil && len(wantedMACs) > 0 {
		lookup := make([]string, 0, len(wantedMACs))
		for mac := range wantedMACs {
			lookup = append(lookup, mac)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 250*time.Millisecond)
		durable, err := readDurableDHCPSignals(ctx, repo.DB, lookup)
		cancel()
		if err != nil {
			response["durable_status"] = "unavailable"
		} else {
			for i := range durable {
				mergePassiveSignal(byKey, &durable[i])
			}
		}
	} else {
		response["durable_status"] = "unavailable"
	}
	if len(ips) > 0 && len(sensors) > 0 && repo.DB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 250*time.Millisecond)
		clients, err := readPassiveClientSignals(ctx, repo.DB, ips, sensors)
		cancel()
		if err != nil {
			response["client_status"] = "unavailable"
		} else {
			response["client_status"] = "ready"
			for i := range clients {
				mergePassiveSignal(clientByKey, &clients[i])
			}
		}
	}
	for _, signal := range cachedPassiveSignals() {
		if (signal.MAC != "" && wantedMACs[signal.MAC]) || (signal.IP != "" && wantedIPs[signal.IP]) {
			mergeCachedPassiveSignal(byKey, signal)
		}
	}
	items := make([]PassiveSignal, 0, len(byKey)+len(clientByKey))
	for _, signal := range byKey {
		items = append(items, *signal)
	}
	for _, signal := range clientByKey {
		items = append(items, *signal)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].MAC+items[i].IP < items[j].MAC+items[j].IP })
	response["items"] = items
	writeJSON(w, 200, response)
}

// Once a durable DHCP fact exists, a newer log-tail glimpse must not replace
// its event ID or attach that ID to fields from an unprojected message.
func mergeCachedPassiveSignal(byKey map[string]*PassiveSignal, signal PassiveSignal) {
	if current := byKey[passiveSignalKey(&signal)]; current != nil && current.DHCPEvidenceID != "" && signal.DHCPObservedAt != "" {
		signal.DHCPHostname, signal.DHCPVendorClass, signal.DHCPOptions = "", "", ""
		signal.DHCPClientIDHWType, signal.DHCPObservedAt, signal.DHCPEvidenceID = "", "", ""
		signal.DHCPOption93Present = false
		signal.OSFamily, signal.OSConfidence, signal.OSEvidence, signal.OSConflict = "", "", "", false
		signal.DeviceHint = ""
	}
	mergePassiveSignal(byKey, &signal)
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

func passiveLogSensorID() string {
	sensor := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_SENSOR_ID"))
	if path := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_CAPTURE_SCOPE_CONFIG")); path != "" {
		scope, err := normalized.LoadCaptureScope(path)
		if err != nil || scope == nil || (sensor != "" && sensor != scope.SensorID) {
			return ""
		}
		return scope.SensorID
	}
	return sensor
}

func readTTLSignals(path string, add func(*PassiveSignal)) {
	lines := tailJSONLines(path, 32<<20)
	for _, line := range lines {
		var event struct {
			TS              float64 `json:"ts"`
			SourceEventType string  `json:"source_event_type"`
			Observer        struct {
				SensorID string `json:"sensor_id"`
			} `json:"observer"`
			Subject struct {
				IP   string `json:"ip"`
				MAC  string `json:"mac"`
				VLAN string `json:"vlan"`
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
		add(&PassiveSignal{SensorID: event.Observer.SensorID, IP: event.Subject.IP, MAC: mac, TTL: event.Payload.TTL, OSHint: ttlOSHint(event.Payload.TTL), TTLVLAN: event.Subject.VLAN, TTLObservedAt: passiveTimestamp(event.TS)})
	}
}

func readDHCPSignals(path, sensor string, add func(*PassiveSignal)) {
	lines := tailJSONLines(path, 16<<20)
	for _, line := range lines {
		var event struct {
			TS               float64 `json:"ts"`
			MAC              string  `json:"mac"`
			RequestedAddr    string  `json:"requested_addr"`
			HostName         string  `json:"host_name"`
			VendorClass      string  `json:"vendor_class"`
			RequestedOptions string  `json:"requested_options"`
			CaptureVLAN      string  `json:"capture_vlan"`
			MessageType      string  `json:"msg_types"`
			ClientIDHWType   int     `json:"client_id_hwtype"`
			Option93Present  bool    `json:"option93_present"`
		}
		if json.Unmarshal(line, &event) != nil || event.MAC == "" || !strings.Contains(strings.ToUpper(event.MessageType), "REQUEST") {
			continue
		}
		signal := &PassiveSignal{
			SensorID:            sensor,
			IP:                  event.RequestedAddr,
			MAC:                 strings.ToLower(strings.TrimSpace(event.MAC)),
			DHCPHostname:        event.HostName,
			DHCPVendorClass:     event.VendorClass,
			DHCPOptions:         event.RequestedOptions,
			DHCPVLAN:            event.CaptureVLAN,
			DHCPObservedAt:      passiveTimestamp(event.TS),
			DHCPOption93Present: event.Option93Present,
		}
		if event.ClientIDHWType > 0 {
			signal.DHCPClientIDHWType = fmt.Sprint(event.ClientIDHWType)
		}
		enrichDHCPVendor(signal)
		add(signal)
	}
}

func enrichDHCPVendor(signal *PassiveSignal) {
	vendor := strings.ToLower(signal.DHCPVendorClass)
	if strings.Contains(vendor, "msft 5.0") {
		signal.OSFamily, signal.OSConfidence, signal.OSEvidence = "Windows", "medium", "DHCP option 60: "+signal.DHCPVendorClass
	} else if strings.Contains(vendor, "android-dhcp") {
		signal.OSFamily, signal.OSConfidence, signal.OSEvidence = "Android", "medium", "DHCP option 60: "+signal.DHCPVendorClass
	}
	for _, networkVendor := range []string{"ruijie", "h3c", "huawei", "cisco", "aruba", "juniper", "tp-link", "tplink", "zyxel"} {
		if strings.Contains(vendor, networkVendor) {
			signal.DeviceHint = "网络设备"
			break
		}
	}
}

func passiveTimestamp(ts float64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(0, int64(ts*float64(time.Second))).UTC().Format(time.RFC3339)
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
