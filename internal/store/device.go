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
	sort.Slice(items, func(i, j int) bool {
		if items[i].SuspectedDeviceCount != items[j].SuspectedDeviceCount {
			return items[i].SuspectedDeviceCount > items[j].SuspectedDeviceCount
		}
		if len(items[i].Conflicts) != len(items[j].Conflicts) {
			return len(items[i].Conflicts) > len(items[j].Conflicts)
		}
		if items[i].LastSeen != items[j].LastSeen {
			return items[i].LastSeen > items[j].LastSeen
		}
		return items[i].IP < items[j].IP
	})
	return items
}

func filterDeviceInventories(items []IPDeviceInventory, query Query) []IPDeviceInventory {
	q := strings.ToLower(strings.TrimSpace(query.Q))
	filtered := make([]IPDeviceInventory, 0, len(items))
	for _, item := range items {
		if query.SrcIP != "" && item.IP != query.SrcIP {
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
						FirstSeen:       draft.timestamp,
						LastSeen:        draft.timestamp,
						EventIDs:        []string{},
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

func signalDrafts(event normalized.Event) []deviceSignalDraft {
	drafts := []deviceSignalDraft{}
	add := func(source, kind, value, strength string, confidence float64, weight int) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		drafts = append(drafts, deviceSignalDraft{
			source:     source,
			kind:       kind,
			value:      value,
			normalized: normalizeSignalValue(kind, value),
			strength:   strength,
			confidence: confidence,
			weight:     weight,
			eventID:    event.EventID,
			timestamp:  event.Timestamp,
		})
	}

	if event.Type == "device" {
		source := stringFromMap(event.Payload, "origin")
		if source == "" {
			source = "device"
		}
		add(source, "mac", firstMapString(event.Payload, "mac", "mac_address"), "strong", 0.92, 90)
		add(source, "oui_vendor", firstMapString(event.Payload, "oui_vendor", "vendor", "brand"), "strong", 0.88, 80)
		add(source, "device_name", firstMapString(event.Payload, "device_name", "hostname", "name"), "strong", 0.82, 70)
		add(source, "os_family", firstMapString(event.Payload, "os", "os_family"), "strong", 0.82, 70)
		add(source, "model", stringFromMap(event.Payload, "model"), "strong", 0.84, 75)
	}

	ua := stringFromMap(event.Payload, "user_agent")
	if ua != "" {
		add("http_ua", "user_agent", ua, "weak", 0.35, 20)
		inferred := inferDeviceFromUA(ua)
		add("http_ua", "ua_os_family", inferred.osFamily, "weak", 0.38, 22)
		add("http_ua", "ua_brand", inferred.brand, "weak", 0.32, 18)
		add("http_ua", "ua_device_type", inferred.deviceType, "weak", 0.34, 18)
		add("http_ua", "ua_model", inferred.model, "weak", 0.32, 18)
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
			if signal.Strength == "strong" && (signal.Kind == "device_name" || signal.Kind == "model") {
				groups["strong:"+signal.Kind+":"+signal.NormalizedValue] = append(groups["strong:"+signal.Kind+":"+signal.NormalizedValue], signal)
			}
		}
	}
	if len(groups) == 0 {
		for _, signal := range signals {
			if signal.Strength == "medium" && (signal.Kind == "ja3" || signal.Kind == "ja4") {
				groups["medium:"+signal.Kind+":"+signal.NormalizedValue] = append(groups["medium:"+signal.Kind+":"+signal.NormalizedValue], signal)
			}
		}
	}
	if len(groups) == 0 {
		groups["weak:bundle"] = weakSignals(signals)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	devices := make([]ObservedDevice, 0, len(keys))
	for _, key := range keys {
		groupSignals := attachWeakContext(groups[key], signals)
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
	}
	sort.Strings(device.Fingerprints)
	device.Confidence = deviceConfidence(device)
	device.Label = deviceLabel(device)
	device.Summary = deviceSummary(device)
	return device
}

func applyDeviceSignal(device *ObservedDevice, signal DeviceSignal) {
	switch signal.Kind {
	case "oui_vendor":
		if signal.Strength == "strong" {
			device.Vendor = signal.Value
			device.Brand = signal.Value
		}
	case "os_family", "ua_os_family":
		if device.OSFamily == "unknown" || signal.Strength == "strong" {
			device.OSFamily = signal.Value
		}
	case "ua_brand":
		if device.Brand == "unknown" {
			device.Brand = signal.Value
		}
	case "ua_device_type":
		if device.DeviceType == "unknown" {
			device.DeviceType = signal.Value
		}
	case "model", "ua_model":
		if device.Model == "unknown" || signal.Strength == "strong" {
			device.Model = signal.Value
		}
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
	addConflict("ua_conflict", "weak", "同一 IP 出现多个 UA，只作为弱信号；需要结合 JA3/JA4、DHCP/OUI 或 TCP 指纹确认", signalValues(byKind["user_agent"]), 0.35, lastSeen)
	addConflict("brand_os_conflict", "weak", "同一 IP 的 UA 推断品牌/系统存在差异，UA 可伪造，不能单独确认多设备", append(signalValues(byKind["ua_brand"]), signalValues(byKind["ua_os_family"])...), 0.38, lastSeen)
	addConflict("tls_stack_conflict", "medium", "同一 IP 出现多个 TLS JA3/JA4 指纹，提示可能存在多客户端栈", append(signalValues(byKind["ja3"]), signalValues(byKind["ja4"])...), 0.62, lastSeen)
	addConflict("tcp_stack_conflict", "medium", "同一 IP 出现多个 TCP 栈侧信号，需结合采集完整性复核", append(signalValues(byKind["ttl"]), signalValues(byKind["ipid"])...), 0.58, lastSeen)
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

func attachWeakContext(primary []DeviceSignal, all []DeviceSignal) []DeviceSignal {
	seen := map[string]struct{}{}
	items := make([]DeviceSignal, 0, len(primary)+6)
	for _, signal := range primary {
		seen[signal.SignalID] = struct{}{}
		items = append(items, signal)
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
	for _, device := range devices {
		if device.StrongSignalCount > 0 || device.MediumSignalCount > 0 {
			return len(devices)
		}
	}
	return 1
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
	case "multi_candidate":
		return fmt.Sprintf("当前观测到 %d 个设备候选；需优先查看强/中信号来源确认是否共享上网", inventory.SuspectedDeviceCount)
	default:
		return "当前观测到单个设备候选；仍需结合 DHCP/OUI/TCP 指纹等强信号提升准确性"
	}
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
