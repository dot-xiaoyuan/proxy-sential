package store

import (
	"fmt"
	"sort"
	"strings"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

type deviceSignalDraft struct {
	source     string
	kind       string
	value      string
	normalized string
	strength   string
	confidence float64
	weight     int
	entityRole string
	accountID  string
	endpointID string
	accessID   string
	eventID    string
	timestamp  string
}

type deviceSignalBucket struct {
	DeviceSignal
	eventSet map[string]struct{}
}

type deviceInference struct {
	brand      string
	vendor     string
	osFamily   string
	osVersion  string
	deviceType string
	model      string
	label      string
}

const (
	defaultDeviceInventoryWeakEventLimit   = 20000
	defaultDeviceInventoryStrongEventLimit = 50000
)

func BuildDeviceInventory(ip string, window string, events []normalized.Event, snapshot risk.Snapshot) IPDeviceInventory {
	if window == "" {
		window = "latest-run"
	}
	selected := make([]normalized.Event, 0, len(events))
	for _, event := range events {
		if subjectIP(event) == ip || stringFromMap(event.Flow, "src_ip") == ip {
			selected = append(selected, event)
		}
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Timestamp != selected[j].Timestamp {
			return selected[i].Timestamp < selected[j].Timestamp
		}
		return selected[i].EventID < selected[j].EventID
	})
	signals := buildDeviceSignals(ip, selected)
	devices := buildObservedDevices(ip, signals)
	conflicts := buildDeviceConflicts(ip, signals, devices)
	firstSeen, lastSeen := eventTimeRange(selected)
	inventory := IPDeviceInventory{
		IP:        ip,
		Window:    window,
		Signals:   signals,
		Devices:   devices,
		Conflicts: conflicts,
		FirstSeen: firstSeen,
		LastSeen:  lastSeen,
	}
	inventory.SuspectedDeviceCount = suspectedDeviceCount(devices, signals)
	inventory.Confidence = inventoryConfidence(devices, signals, conflicts, snapshot)
	inventory.Status = inventoryStatus(inventory)
	inventory.Summary = inventorySummary(inventory)
	return inventory
}

func BuildDeviceInventories(window string, events []normalized.Event, risks map[string]risk.Snapshot) []IPDeviceInventory {
	byIP := map[string][]normalized.Event{}
	for _, event := range events {
		ip := subjectIP(event)
		if ip == "" {
			ip = stringFromMap(event.Flow, "src_ip")
		}
		if ip == "" {
			continue
		}
		byIP[ip] = append(byIP[ip], event)
	}
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	items := make([]IPDeviceInventory, 0, len(ips))
	for _, ip := range ips {
		items = append(items, BuildDeviceInventory(ip, window, byIP[ip], risks[ip]))
	}
	sortDeviceInventories(items)
	return items
}

func sortDeviceInventories(items []IPDeviceInventory) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].SuspectedDeviceCount != items[j].SuspectedDeviceCount {
			return items[i].SuspectedDeviceCount > items[j].SuspectedDeviceCount
		}
		if len(items[i].Conflicts) != len(items[j].Conflicts) {
			return len(items[i].Conflicts) > len(items[j].Conflicts)
		}
		if inventoryStrongSignalCount(items[i]) != inventoryStrongSignalCount(items[j]) {
			return inventoryStrongSignalCount(items[i]) > inventoryStrongSignalCount(items[j])
		}
		if items[i].Confidence != items[j].Confidence {
			return items[i].Confidence > items[j].Confidence
		}
		if items[i].LastSeen != items[j].LastSeen {
			return items[i].LastSeen > items[j].LastSeen
		}
		return items[i].IP < items[j].IP
	})
}

func filterDeviceInventories(items []IPDeviceInventory, query Query) []IPDeviceInventory {
	q := strings.ToLower(strings.TrimSpace(query.Q))
	filtered := make([]IPDeviceInventory, 0, len(items))
	for _, item := range items {
		if query.SrcIP != "" && item.IP != query.SrcIP {
			continue
		}
		if !query.IncludeWeak && (item.Confidence < 0.80 || item.Status == "weak_signals_only") {
			continue
		}
		if q != "" && !inventoryMatchesQuery(item, q) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func inventoryMatchesQuery(item IPDeviceInventory, q string) bool {
	if strings.Contains(strings.ToLower(item.IP), q) || strings.Contains(strings.ToLower(item.Summary), q) || strings.Contains(strings.ToLower(item.Status), q) {
		return true
	}
	for _, device := range item.Devices {
		if strings.Contains(strings.ToLower(device.Label), q) ||
			strings.Contains(strings.ToLower(device.Brand), q) ||
			strings.Contains(strings.ToLower(device.Vendor), q) ||
			strings.Contains(strings.ToLower(device.OSFamily), q) ||
			strings.Contains(strings.ToLower(device.DeviceType), q) ||
			strings.Contains(strings.ToLower(device.Model), q) {
			return true
		}
	}
	for _, signal := range item.Signals {
		if strings.Contains(strings.ToLower(signal.Value), q) || strings.Contains(strings.ToLower(signal.Kind), q) || strings.Contains(strings.ToLower(signal.Source), q) {
			return true
		}
	}
	return false
}

func mergeEventSamples(primary []normalized.Event, extra []normalized.Event) []normalized.Event {
	if len(extra) == 0 {
		return primary
	}
	seen := map[string]struct{}{}
	merged := make([]normalized.Event, 0, len(primary)+len(extra))
	add := func(event normalized.Event) {
		key := event.EventID
		if key == "" {
			key = shortHash(event.Source + "|" + event.SourceEventType + "|" + event.Type + "|" + event.Timestamp + "|" + subjectIP(event))
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		merged = append(merged, event)
	}
	for _, event := range primary {
		add(event)
	}
	for _, event := range extra {
		add(event)
	}
	return merged
}

func buildDeviceSignals(ip string, events []normalized.Event) []DeviceSignal {
	buckets := map[string]*deviceSignalBucket{}
	for _, event := range events {
		for _, draft := range signalDrafts(event) {
			if draft.value == "" || draft.normalized == "" {
				continue
			}
			key := strings.Join([]string{draft.source, draft.kind, draft.normalized}, "|")
			bucket := buckets[key]
			if bucket == nil {
				bucket = &deviceSignalBucket{
					DeviceSignal: DeviceSignal{
						SignalID:        "signal-" + shortHash("device-signal|"+ip+"|"+key),
						IP:              ip,
						Source:          draft.source,
						Kind:            draft.kind,
						Value:           draft.value,
						NormalizedValue: draft.normalized,
						Strength:        draft.strength,
						Confidence:      draft.confidence,
						Weight:          draft.weight,
						EntityRole:      draft.entityRole,
						AccountID:       draft.accountID,
						EndpointID:      draft.endpointID,
						AccessID:        draft.accessID,
						FirstSeen:       draft.timestamp,
						LastSeen:        draft.timestamp,
						EventIDs:        []string{},
						EventIDsSample:  []string{},
					},
					eventSet: map[string]struct{}{},
				}
				buckets[key] = bucket
			}
			if draft.timestamp < bucket.FirstSeen || bucket.FirstSeen == "" {
				bucket.FirstSeen = draft.timestamp
			}
			if draft.timestamp > bucket.LastSeen {
				bucket.LastSeen = draft.timestamp
			}
			if draft.eventID != "" {
				bucket.eventSet[draft.eventID] = struct{}{}
			}
		}
	}
	signals := make([]DeviceSignal, 0, len(buckets))
	for _, bucket := range buckets {
		for eventID := range bucket.eventSet {
			bucket.EventIDs = append(bucket.EventIDs, eventID)
		}
		sort.Strings(bucket.EventIDs)
		if len(bucket.EventIDs) > 20 {
			bucket.EventIDs = bucket.EventIDs[:20]
		}
		bucket.EventIDsSample = append([]string{}, bucket.EventIDs...)
		bucket.SeenCount = len(bucket.eventSet)
		if bucket.SeenCount == 0 {
			bucket.SeenCount = 1
		}
		signals = append(signals, bucket.DeviceSignal)
	}
	sort.Slice(signals, func(i, j int) bool {
		if signals[i].Strength != signals[j].Strength {
			return signalRank(signals[i].Strength) > signalRank(signals[j].Strength)
		}
		if signals[i].LastSeen != signals[j].LastSeen {
			return signals[i].LastSeen > signals[j].LastSeen
		}
		return signals[i].SignalID < signals[j].SignalID
	})
	return limitDeviceSignals(signals)
}

func BuildDeviceInventoryFromSignals(ip string, window string, signals []DeviceSignal, snapshot risk.Snapshot) IPDeviceInventory {
	if window == "" {
		window = "latest-run"
	}
	sort.Slice(signals, func(i, j int) bool {
		if signals[i].Strength != signals[j].Strength {
			return signalRank(signals[i].Strength) > signalRank(signals[j].Strength)
		}
		if signals[i].LastSeen != signals[j].LastSeen {
			return signals[i].LastSeen > signals[j].LastSeen
		}
		return signals[i].SignalID < signals[j].SignalID
	})
	signals = limitDeviceSignals(signals)
	devices := buildObservedDevices(ip, signals)
	conflicts := buildDeviceConflicts(ip, signals, devices)
	firstSeen, lastSeen := signalTimeRange(signals)
	inventory := IPDeviceInventory{
		IP:        ip,
		Window:    window,
		Signals:   signals,
		Devices:   devices,
		Conflicts: conflicts,
		FirstSeen: firstSeen,
		LastSeen:  lastSeen,
	}
	inventory.SuspectedDeviceCount = suspectedDeviceCount(devices, signals)
	inventory.Confidence = inventoryConfidence(devices, signals, conflicts, snapshot)
	inventory.Status = inventoryStatus(inventory)
	inventory.Summary = inventorySummary(inventory)
	return inventory
}

func signalDrafts(event normalized.Event) []deviceSignalDraft {
	drafts := []deviceSignalDraft{}
	entityRole := stringFromMap(event.Subject, "entity_role")
	if isInfrastructureEntityRole(entityRole) {
		return drafts
	}
	accountID := stringFromMap(event.Subject, "account_id")
	endpointID := stringFromMap(event.Subject, "endpoint_id")
	accessID := stringFromMap(event.Subject, "access_id")
	add := func(source, kind, value, strength string, confidence float64, weight int) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		normalized := normalizeSignalValue(kind, value)
		if kind == "mac" {
			value = normalized
		}
		drafts = append(drafts, deviceSignalDraft{
			source:     source,
			kind:       kind,
			value:      value,
			normalized: normalized,
			strength:   strength,
			confidence: confidence,
			weight:     weight,
			entityRole: entityRole,
			accountID:  accountID,
			endpointID: endpointID,
			accessID:   accessID,
			eventID:    event.EventID,
			timestamp:  event.Timestamp,
		})
	}

	if event.Type == "device" {
		source := stringFromMap(event.Payload, "origin")
		if source == "" {
			source = "device"
		}
		mac := firstMapString(event.Payload, "mac", "client_mac", "mac_address")
		if mac == "" {
			mac = firstMapString(event.Subject, "mac")
		}
		add(source, "mac", mac, "strong", 0.92, 90)
		add(source, "oui_vendor", firstMapString(event.Payload, "oui_vendor", "vendor", "brand"), "strong", 0.88, 80)
		add(source, "device_name", firstMapString(event.Payload, "device_name", "hostname", "name"), "strong", 0.82, 70)
		add(source, "os_family", firstMapString(event.Payload, "os", "os_family"), "strong", 0.82, 70)
		add(source, "model", stringFromMap(event.Payload, "model"), "strong", 0.84, 75)
		add(source, "dhcp_vendor_class", stringFromMap(event.Payload, "vendor_class"), "strong", 0.8, 68)
		add(source, "device_hint", stringFromMap(event.Payload, "device_hint"), "strong", 0.84, 72)
		add(source, "dhcp_requested_options", stringFromMap(event.Payload, "requested_options"), "medium", 0.7, 56)
		add(source, "software_name", stringFromMap(event.Payload, "software_name"), "strong", 0.74, 62)
		add(source, "software_version", stringFromMap(event.Payload, "software_version"), "medium", 0.68, 52)
		inferred := inferDeviceFromDHCP(event.Payload)
		add(source, "os_family", inferred.osFamily, "strong", 0.82, 70)
		add(source, "brand", inferred.brand, "strong", 0.78, 62)
		add(source, "device_type", inferred.deviceType, "strong", 0.76, 60)
		add(source, "model", inferred.model, "strong", 0.76, 60)
	}

	ua := stringFromMap(event.Payload, "user_agent")
	if ua != "" {
		add("http_ua", "user_agent", ua, "weak", 0.35, 20)
	}
	add("tls_fingerprint", "ja3", stringFromMap(event.Payload, "ja3"), "medium", 0.62, 48)
	add("tls_fingerprint", "ja4", stringFromMap(event.Payload, "ja4"), "medium", 0.64, 50)
	if ttl := intFromMap(event.Flow, "ttl"); ttl > 0 {
		add("tcp_stack", "ttl", fmt.Sprintf("%d", ttl), "medium", 0.58, 42)
	}
	if ipid := intFromMap(event.Flow, "ipid"); ipid > 0 {
		add("tcp_stack", "ipid", fmt.Sprintf("%d", ipid), "medium", 0.5, 34)
	}
	domain := eventDomain(event)
	if domain != "" {
		add("access_pattern", "domain", domain, "weak", 0.2, 8)
	}
	return drafts
}

func limitDeviceSignals(signals []DeviceSignal) []DeviceSignal {
	result := make([]DeviceSignal, 0, len(signals))
	weakDomains := []DeviceSignal{}
	weakOther := []DeviceSignal{}
	for _, signal := range signals {
		if signal.Strength == "strong" || signal.Strength == "medium" {
			result = append(result, signal)
			continue
		}
		if signal.Kind == "domain" {
			weakDomains = append(weakDomains, signal)
			continue
		}
		weakOther = append(weakOther, signal)
	}
	sort.Slice(weakDomains, func(i, j int) bool {
		if len(weakDomains[i].EventIDs) != len(weakDomains[j].EventIDs) {
			return len(weakDomains[i].EventIDs) > len(weakDomains[j].EventIDs)
		}
		if weakDomains[i].LastSeen != weakDomains[j].LastSeen {
			return weakDomains[i].LastSeen > weakDomains[j].LastSeen
		}
		return weakDomains[i].Value < weakDomains[j].Value
	})
	if len(weakDomains) > 12 {
		weakDomains = weakDomains[:12]
	}
	if len(weakOther) > 24 {
		weakOther = weakOther[:24]
	}
	result = append(result, weakOther...)
	result = append(result, weakDomains...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Strength != result[j].Strength {
			return signalRank(result[i].Strength) > signalRank(result[j].Strength)
		}
		if result[i].LastSeen != result[j].LastSeen {
			return result[i].LastSeen > result[j].LastSeen
		}
		return result[i].SignalID < result[j].SignalID
	})
	return result
}

func buildObservedDevices(ip string, signals []DeviceSignal) []ObservedDevice {
	if len(signals) == 0 {
		return []ObservedDevice{}
	}
	groups := map[string][]DeviceSignal{}
	for _, signal := range signals {
		if signal.Strength == "strong" && signal.Kind == "mac" {
			groups["strong:mac:"+signal.NormalizedValue] = append(groups["strong:mac:"+signal.NormalizedValue], signal)
		}
	}
	if len(groups) == 0 {
		for _, signal := range signals {
			if signal.Strength == "strong" && (signal.Kind == "device_name" || signal.Kind == "model" || signal.Kind == "software_name") {
				groups["strong:"+signal.Kind+":"+signal.NormalizedValue] = append(groups["strong:"+signal.Kind+":"+signal.NormalizedValue], signal)
			}
		}
	}
	if len(groups) == 0 {
		// TLS fingerprints identify software stacks, not physical endpoints.
		// Keep all protocol clues in inventory.Signals without copying them into
		// thousands of invented device entities in every historical snapshot.
		weak := []DeviceSignal{}
		for _, signal := range signals {
			if signal.Strength == "weak" {
				weak = append(weak, signal)
			}
		}
		if len(weak) == 0 {
			return []ObservedDevice{}
		}
		groups["weak:bundle"] = weak
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	devices := make([]ObservedDevice, 0, len(keys))
	for _, key := range keys {
		groupSignals := groups[key]
		if key != "weak:bundle" {
			groupSignals = attachDeviceContext(groupSignals, signals)
		}
		devices = append(devices, observedDevice(ip, key, groupSignals))
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Confidence != devices[j].Confidence {
			return devices[i].Confidence > devices[j].Confidence
		}
		if devices[i].LastSeen != devices[j].LastSeen {
			return devices[i].LastSeen > devices[j].LastSeen
		}
		return devices[i].DeviceID < devices[j].DeviceID
	})
	return devices
}

func observedDevice(ip string, groupKey string, signals []DeviceSignal) ObservedDevice {
	device := ObservedDevice{
		DeviceID:     "device-" + shortHash("device|"+ip+"|"+groupKey),
		IP:           ip,
		Brand:        "unknown",
		Vendor:       "unknown",
		OSFamily:     "unknown",
		DeviceType:   "unknown",
		EntityRole:   "unknown",
		Model:        "unknown",
		Signals:      signals,
		Fingerprints: []string{},
	}
	for _, signal := range signals {
		device.SignalCount++
		switch signal.Strength {
		case "strong":
			device.StrongSignalCount++
		case "medium":
			device.MediumSignalCount++
		default:
			device.WeakSignalCount++
		}
		if device.FirstSeen == "" || signal.FirstSeen < device.FirstSeen {
			device.FirstSeen = signal.FirstSeen
		}
		if signal.LastSeen > device.LastSeen {
			device.LastSeen = signal.LastSeen
		}
		applyDeviceSignal(&device, signal)
		applyDeviceIdentity(&device, signal)
	}
	if device.EntityRole == "unknown" && (device.StrongSignalCount > 0 || device.MediumSignalCount > 0) && !hasExplicitUnknownRole(signals) {
		device.EntityRole = "endpoint"
	}
	sort.Strings(device.Fingerprints)
	qualifyPortableDHCPProfile(&device)
	device.Confidence = deviceConfidence(device)
	device.Label = deviceLabel(device)
	device.Summary = deviceSummary(device)
	return device
}

func hasExplicitUnknownRole(signals []DeviceSignal) bool {
	for _, signal := range signals {
		if signal.EntityRole == "unknown" {
			return true
		}
	}
	return false
}

func applyDeviceIdentity(device *ObservedDevice, signal DeviceSignal) {
	if device.EntityRole == "unknown" && signal.EntityRole != "" {
		device.EntityRole = signal.EntityRole
	}
	if device.AccountID == "" {
		device.AccountID = signal.AccountID
	}
	if device.EndpointID == "" {
		device.EndpointID = signal.EndpointID
	}
	if device.AccessID == "" {
		device.AccessID = signal.AccessID
	}
}

func applyDeviceSignal(device *ObservedDevice, signal DeviceSignal) {
	switch signal.Kind {
	case "oui_vendor":
		if signal.Strength == "strong" {
			device.Vendor = signal.Value
		}
	case "os_family":
		if device.OSFamily == "unknown" || signal.Strength == "strong" {
			device.OSFamily = signal.Value
		}
	case "brand":
		if device.Brand == "unknown" {
			device.Brand = signal.Value
		}
	case "device_type":
		if device.DeviceType == "unknown" {
			device.DeviceType = signal.Value
		}
	case "model":
		if device.Model == "unknown" || signal.Strength == "strong" {
			device.Model = signal.Value
		}
	case "dhcp_vendor_class":
		device.Fingerprints = append(device.Fingerprints, "dhcp_vendor:"+signal.Value)
	case "dhcp_requested_options":
		device.Fingerprints = append(device.Fingerprints, "dhcp_options:"+signal.Value)
	case "software_name":
		device.Fingerprints = append(device.Fingerprints, "software:"+signal.Value)
	case "software_version":
		device.Fingerprints = append(device.Fingerprints, "software_version:"+signal.Value)
	case "ja3", "ja4":
		device.Fingerprints = append(device.Fingerprints, signal.Kind+":"+signal.Value)
	}
}

func buildDeviceConflicts(ip string, signals []DeviceSignal, devices []ObservedDevice) []DeviceConflict {
	conflicts := []DeviceConflict{}
	addConflict := func(conflictType, strength, summary string, samples []string, confidence float64, lastSeen string) {
		if len(samples) < 2 {
			return
		}
		conflicts = append(conflicts, DeviceConflict{
			ConflictID:       "device-conflict-" + shortHash(strings.Join(append([]string{ip, conflictType}, samples...), "|")),
			IP:               ip,
			Type:             conflictType,
			Strength:         strength,
			Confidence:       confidence,
			Summary:          summary,
			Samples:          limitStrings(samples, 8),
			LastSeen:         lastSeen,
			RelatedDeviceIDs: deviceIDs(devices),
		})
	}
	byKind := signalsByKind(signals)
	lastSeen := latestSignalTime(signals)
	addConflict("dhcp_stack_conflict", "medium", "DHCP 系统家族线索存在分歧；客户端软件、系统升级或先后租约均可能造成差异，不能据此确认共享", dhcpFamilyConflictSamples(signals), 0.62, lastSeen)
	tlsSamples := []string{}
	for _, kind := range []string{"ja3", "ja4"} {
		values := signalValues(byKind[kind])
		if len(values) < 2 {
			continue
		}
		for _, value := range values {
			tlsSamples = append(tlsSamples, kind+":"+value)
		}
	}
	addConflict("tls_stack_conflict", "medium", "同类 TLS 指纹存在差异，可能来自同一设备的不同应用；此线索不表示设备数量或共享行为", tlsSamples, 0.62, lastSeen)
	// TTL and IPID are different packet fields. Route changes and ordinary
	// counters are not TCP stack fingerprints; retain their raw signals only.
	if strongCount(devices) >= 2 {
		addConflict("multi_observed_device", "strong", "同一 IP 下存在多个强信号设备候选", deviceLabels(devices), 0.86, lastSeen)
	}
	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Strength != conflicts[j].Strength {
			return signalRank(conflicts[i].Strength) > signalRank(conflicts[j].Strength)
		}
		return conflicts[i].ConflictID < conflicts[j].ConflictID
	})
	return conflicts
}

func dhcpFamilyConflictSamples(signals []DeviceSignal) []string {
	families := map[string]struct{}{}
	for _, signal := range signals {
		if signal.Source != "dhcp" {
			continue
		}
		var fields map[string]any
		switch signal.Kind {
		case "device_hint":
			fields = map[string]any{"device_hint": signal.Value}
		case "dhcp_vendor_class":
			fields = map[string]any{"vendor_class": signal.Value}
		default:
			continue
		}
		inferred := inferDeviceFromDHCP(fields)
		family := inferred.osFamily
		switch family {
		case "":
			continue
		case "Android", "ChromeOS", "Linux":
			family = "Linux 系客户端"
		case "iOS", "iPadOS", "macOS":
			family = "Apple 系客户端"
		}
		families[family] = struct{}{}
	}
	result := make([]string, 0, len(families))
	for family := range families {
		result = append(result, family)
	}
	sort.Strings(result)
	return result
}

// Re-evaluate explanations on read so an immutable historical snapshot does
// not keep presenting an obsolete conflict rule as current physical proof.
// The stored source signals and candidate identities remain untouched.
func refreshDeviceInventoryConflicts(inventory *IPDeviceInventory) {
	for i := range inventory.Devices {
		qualifyPortableDHCPProfile(&inventory.Devices[i])
		inventory.Devices[i].Label = deviceLabel(inventory.Devices[i])
	}
	inventory.Conflicts = buildDeviceConflicts(inventory.IP, inventory.Signals, inventory.Devices)
	inventory.Confidence = inventoryConfidence(inventory.Devices, inventory.Signals, inventory.Conflicts, risk.Snapshot{})
}

func qualifyPortableDHCPProfile(device *ObservedDevice) {
	if device.OSFamily != "Linux" {
		return
	}
	portable := false
	independentDesktop := false
	for _, signal := range device.Signals {
		if signal.Kind == "device_type" && signal.Value == "desktop" && signal.Source != "dhcp" && signal.Source != "software" {
			independentDesktop = true
		}
		if (signal.Kind == "dhcp_vendor_class" || signal.Kind == "software_name" || signal.Kind == "software_version") && normalized.IsPortableDHCPClient(signal.Value) {
			portable = true
		}
		// An independent explicit OS source must remain available.
		if signal.Kind == "os_family" && signal.Value == "Linux" && signal.Source != "dhcp" && signal.Source != "software" {
			return
		}
		if signal.Kind == "device_name" {
			inferred := inferDeviceFromDHCP(map[string]any{"hostname": signal.Value})
			if inferred.osFamily == "Linux" {
				return
			}
		}
	}
	if !portable {
		return
	}
	device.OSFamily = "unknown"
	if device.DeviceType == "desktop" && !independentDesktop {
		device.DeviceType = "unknown"
	}
}

func inferDeviceFromUA(ua string) deviceInference {
	lower := strings.ToLower(ua)
	out := deviceInference{brand: "", vendor: "", osFamily: "", deviceType: "", model: ""}
	switch {
	case strings.Contains(lower, "iphone"):
		out.brand, out.vendor, out.osFamily, out.deviceType, out.model = "Apple", "Apple", "iOS", "mobile", "iPhone"
	case strings.Contains(lower, "ipad"):
		out.brand, out.vendor, out.osFamily, out.deviceType, out.model = "Apple", "Apple", "iPadOS", "tablet", "iPad"
	case strings.Contains(lower, "macintosh") || strings.Contains(lower, "mac os x"):
		out.brand, out.vendor, out.osFamily, out.deviceType, out.model = "Apple", "Apple", "macOS", "desktop", "Mac"
	case strings.Contains(lower, "windows"):
		out.osFamily, out.deviceType = "Windows", "desktop"
	case strings.Contains(lower, "android"):
		out.osFamily, out.deviceType = "Android", "mobile"
		out.brand = androidBrand(lower)
		out.model = androidModel(ua)
	case strings.Contains(lower, "linux"):
		out.osFamily, out.deviceType = "Linux", "desktop"
	case strings.Contains(lower, "curl") || strings.Contains(lower, "python") || strings.Contains(lower, "okhttp") || strings.Contains(lower, "java/") || strings.Contains(lower, "go-http-client"):
		out.deviceType = "client_library"
	}
	if out.brand != "" && out.vendor == "" {
		out.vendor = out.brand
	}
	return out
}

func inferDeviceFromDHCP(payload map[string]any) deviceInference {
	text := normalized.DeviceProfileHintText(payload)
	out := deviceInference{brand: "", vendor: "", osFamily: "", deviceType: "", model: ""}
	switch {
	case strings.Contains(text, "iphone"):
		out.brand, out.vendor, out.osFamily, out.deviceType, out.model = "Apple", "Apple", "iOS", "mobile", "iPhone"
	case strings.Contains(text, "ipad"):
		out.brand, out.vendor, out.osFamily, out.deviceType, out.model = "Apple", "Apple", "iPadOS", "tablet", "iPad"
	case strings.Contains(text, "apple"), strings.Contains(text, "macbook"), strings.Contains(text, "imac"):
		out.brand, out.vendor, out.osFamily, out.deviceType = "Apple", "Apple", "macOS", "desktop"
	case strings.Contains(text, "android"):
		out.osFamily, out.deviceType = "Android", "mobile"
	case strings.Contains(text, "msft"), strings.Contains(text, "microsoft"), strings.Contains(text, "windows"), strings.Contains(text, "desktop-"):
		out.osFamily, out.deviceType = "Windows", "desktop"
	case strings.Contains(text, "chromeos"), strings.Contains(text, "chromebook"):
		out.osFamily, out.deviceType, out.brand = "ChromeOS", "laptop", "Google"
	case strings.Contains(text, "linux"), strings.Contains(text, "ubuntu"), strings.Contains(text, "debian"):
		out.osFamily, out.deviceType = "Linux", "desktop"
	}
	if out.brand != "" && out.vendor == "" {
		out.vendor = out.brand
	}
	return out
}

func androidBrand(lower string) string {
	brands := []string{"samsung", "huawei", "xiaomi", "redmi", "oppo", "vivo", "honor", "oneplus", "pixel", "realme", "meizu", "lenovo", "motorola"}
	for _, brand := range brands {
		if strings.Contains(lower, brand) {
			switch brand {
			case "redmi":
				return "Xiaomi"
			case "pixel":
				return "Google"
			default:
				return strings.ToUpper(brand[:1]) + brand[1:]
			}
		}
	}
	return ""
}

func androidModel(ua string) string {
	lower := strings.ToLower(ua)
	index := strings.Index(lower, "android")
	if index < 0 {
		return ""
	}
	part := ua[index:]
	if semi := strings.Index(part, ";"); semi >= 0 {
		rest := strings.TrimSpace(part[semi+1:])
		if end := strings.Index(rest, ")"); end >= 0 {
			rest = rest[:end]
		}
		if rest != "" && len(rest) <= 80 {
			return rest
		}
	}
	return ""
}

func normalizeSignalValue(kind string, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case "mac":
		return strings.ToLower(strings.ReplaceAll(value, "-", ":"))
	case "user_agent":
		return strings.ToLower(value)
	default:
		return strings.ToLower(value)
	}
}

func weakSignals(signals []DeviceSignal) []DeviceSignal {
	items := []DeviceSignal{}
	for _, signal := range signals {
		if signal.Strength == "weak" {
			items = append(items, signal)
		}
	}
	if len(items) == 0 {
		items = signals
	}
	return items
}

func attachDeviceContext(primary []DeviceSignal, all []DeviceSignal) []DeviceSignal {
	seen := map[string]struct{}{}
	items := make([]DeviceSignal, 0, len(primary)+6)
	primaryEvents := eventIDSet(primary)
	for _, signal := range primary {
		seen[signal.SignalID] = struct{}{}
		items = append(items, signal)
	}
	for _, signal := range all {
		if signal.Strength == "weak" || !sharesEventID(signal, primaryEvents) {
			continue
		}
		if _, ok := seen[signal.SignalID]; ok {
			continue
		}
		items = append(items, signal)
		seen[signal.SignalID] = struct{}{}
	}
	for _, signal := range all {
		if signal.Strength != "weak" {
			continue
		}
		if _, ok := seen[signal.SignalID]; ok {
			continue
		}
		items = append(items, signal)
		seen[signal.SignalID] = struct{}{}
		if len(items) >= len(primary)+6 {
			break
		}
	}
	return items
}

func eventIDSet(signals []DeviceSignal) map[string]struct{} {
	events := map[string]struct{}{}
	for _, signal := range signals {
		for _, eventID := range signal.EventIDs {
			events[eventID] = struct{}{}
		}
	}
	return events
}

func sharesEventID(signal DeviceSignal, events map[string]struct{}) bool {
	if len(events) == 0 {
		return false
	}
	for _, eventID := range signal.EventIDs {
		if _, ok := events[eventID]; ok {
			return true
		}
	}
	return false
}

func deviceConfidence(device ObservedDevice) float64 {
	switch {
	case device.StrongSignalCount > 0:
		return 0.82
	case device.MediumSignalCount > 0:
		return 0.62
	case device.WeakSignalCount > 0:
		return 0.34
	default:
		return 0
	}
}

func suspectedDeviceCount(devices []ObservedDevice, signals []DeviceSignal) int {
	if len(devices) == 0 {
		return 0
	}
	endpoints := 0
	for _, device := range devices {
		if device.EntityRole == "endpoint" && (device.StrongSignalCount > 0 || device.MediumSignalCount > 0) {
			endpoints++
		}
	}
	return endpoints
}

func inventoryConfidence(devices []ObservedDevice, signals []DeviceSignal, conflicts []DeviceConflict, snapshot risk.Snapshot) float64 {
	max := 0.0
	for _, device := range devices {
		if device.Confidence > max {
			max = device.Confidence
		}
	}
	for _, conflict := range conflicts {
		if conflict.Confidence > max {
			max = conflict.Confidence
		}
	}
	if max == 0 && snapshot.Confidence > 0 {
		max = snapshot.Confidence * 0.5
	}
	return roundDeviceConfidence(max)
}

func inventoryStatus(inventory IPDeviceInventory) string {
	if len(inventory.Signals) == 0 {
		return "insufficient_signal"
	}
	if inventory.SuspectedDeviceCount == 0 {
		return "non_endpoint_or_weak"
	}
	if inventory.SuspectedDeviceCount >= 2 {
		return "multi_candidate"
	}
	for _, device := range inventory.Devices {
		if device.StrongSignalCount > 0 || device.MediumSignalCount > 0 {
			return "single_candidate"
		}
	}
	return "weak_signals_only"
}

func inventorySummary(inventory IPDeviceInventory) string {
	switch inventory.Status {
	case "insufficient_signal":
		return "当前标准事件中没有足够设备识别信号，无法判断该 IP 背后设备数量或品牌"
	case "weak_signals_only":
		return "当前仅有 UA/访问行为等弱信号；UA 可伪造，不能据此确认品牌或多设备"
	case "non_endpoint_or_weak":
		return "当前信号不足以确认终端身份；协议差异与基础设施不计入普通设备并发"
	case "multi_candidate":
		return fmt.Sprintf("当前观测到 %d 个设备候选；需优先查看强/中信号来源确认是否共享上网", inventory.SuspectedDeviceCount)
	default:
		if inventoryStrongSignalCount(inventory) > 0 {
			return "当前观测到单个设备候选；已有 DHCP/MAC/设备名等强信号支撑，可作为人工复核的主要依据"
		}
		return "当前观测到单个设备候选；仍需结合 DHCP/OUI/TCP 指纹等强信号提升准确性"
	}
}

func isInfrastructureEntityRole(role string) bool {
	switch role {
	case "infrastructure", "gateway", "nat", "server", "network_device":
		return true
	default:
		return false
	}
}

func inventoryStrongSignalCount(inventory IPDeviceInventory) int {
	count := 0
	for _, device := range inventory.Devices {
		count += device.StrongSignalCount
	}
	if count > 0 {
		return count
	}
	for _, signal := range inventory.Signals {
		if signal.Strength == "strong" {
			count++
		}
	}
	return count
}

func deviceLabel(device ObservedDevice) string {
	parts := []string{}
	if device.Brand != "" && device.Brand != "unknown" {
		parts = append(parts, device.Brand)
	}
	if device.Model != "" && device.Model != "unknown" {
		parts = append(parts, device.Model)
	}
	if device.OSFamily != "" && device.OSFamily != "unknown" {
		parts = append(parts, device.OSFamily)
	}
	if device.DeviceType != "" && device.DeviceType != "unknown" {
		parts = append(parts, device.DeviceType)
	}
	if len(parts) == 0 {
		return "未知设备候选"
	}
	return strings.Join(parts, " / ")
}

func deviceSummary(device ObservedDevice) string {
	if device.StrongSignalCount > 0 {
		return "由 DHCP/mDNS/SSDP/MAC/OUI 等强设备信号支撑"
	}
	if device.MediumSignalCount > 0 {
		return "由 JA3/JA4、TCP 栈等中等强度信号支撑，建议结合强信号复核"
	}
	return "仅由 UA/访问行为弱信号推断，不能作为准确设备识别结论"
}

func eventTimeRange(events []normalized.Event) (string, string) {
	first, last := "", ""
	for _, event := range events {
		if event.Timestamp == "" {
			continue
		}
		if first == "" || event.Timestamp < first {
			first = event.Timestamp
		}
		if event.Timestamp > last {
			last = event.Timestamp
		}
	}
	return first, last
}

func signalTimeRange(signals []DeviceSignal) (string, string) {
	first, last := "", ""
	for _, signal := range signals {
		if signal.FirstSeen != "" && (first == "" || signal.FirstSeen < first) {
			first = signal.FirstSeen
		}
		if signal.LastSeen > last {
			last = signal.LastSeen
		}
	}
	return first, last
}

func signalsByKind(signals []DeviceSignal) map[string][]DeviceSignal {
	result := map[string][]DeviceSignal{}
	for _, signal := range signals {
		result[signal.Kind] = append(result[signal.Kind], signal)
	}
	return result
}

func signalValues(signals []DeviceSignal) []string {
	values := make([]string, 0, len(signals))
	seen := map[string]struct{}{}
	for _, signal := range signals {
		if signal.Value == "" {
			continue
		}
		if _, ok := seen[signal.Value]; ok {
			continue
		}
		seen[signal.Value] = struct{}{}
		values = append(values, signal.Value)
	}
	sort.Strings(values)
	return values
}

func signalRank(strength string) int {
	switch strength {
	case "strong":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func latestSignalTime(signals []DeviceSignal) string {
	latest := ""
	for _, signal := range signals {
		if signal.LastSeen > latest {
			latest = signal.LastSeen
		}
	}
	return latest
}

func strongCount(devices []ObservedDevice) int {
	count := 0
	for _, device := range devices {
		if device.StrongSignalCount > 0 {
			count++
		}
	}
	return count
}

func deviceIDs(devices []ObservedDevice) []string {
	ids := make([]string, 0, len(devices))
	for _, device := range devices {
		ids = append(ids, device.DeviceID)
	}
	sort.Strings(ids)
	return ids
}

func deviceLabels(devices []ObservedDevice) []string {
	labels := make([]string, 0, len(devices))
	for _, device := range devices {
		labels = append(labels, device.Label)
	}
	sort.Strings(labels)
	return labels
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func roundDeviceConfidence(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}

func firstMapString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringFromMap(values, key); value != "" {
			return value
		}
	}
	return ""
}
