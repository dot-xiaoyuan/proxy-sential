package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

type Options struct {
	Window time.Duration
}

type Stats struct {
	Read      int `json:"read"`
	Accepted  int `json:"accepted"`
	Duplicate int `json:"duplicate"`
	Skipped   int `json:"skipped"`
	Malformed int `json:"malformed"`
}

type Result struct {
	Stats    Stats      `json:"stats"`
	MaxTime  string     `json:"max_time,omitempty"`
	Evidence []Evidence `json:"evidence"`
}

type Evidence struct {
	EvidenceID  string   `json:"evidence_id"`
	IP          string   `json:"ip"`
	SubjectType string   `json:"subject_type,omitempty"`
	SubjectID   string   `json:"subject_id,omitempty"`
	AccountID   string   `json:"account_id,omitempty"`
	EndpointID  string   `json:"endpoint_id,omitempty"`
	Type        string   `json:"type"`
	Window      string   `json:"window"`
	Score       int      `json:"score"`
	Confidence  float64  `json:"confidence"`
	Severity    string   `json:"severity"`
	Reason      string   `json:"reason"`
	Samples     []string `json:"samples"`
	CreatedAt   string   `json:"created_at"`
}

type parsedEvent struct {
	Event normalized.Event
	Time  time.Time
}

type ipSignals struct {
	userAgents          map[string]struct{}
	ja3                 map[string]struct{}
	ja4                 map[string]struct{}
	domains             map[string]struct{}
	dstPorts            map[string]struct{}
	deviceProfiles      map[string]struct{}
	deviceFamilies      map[string]struct{}
	vpnRuleMatches      map[string]struct{}
	vpnDomainHints      map[string]struct{}
	encryptedTransports map[string]struct{}
}

type accountSignals struct {
	ips          map[string]struct{}
	macs         map[string]struct{}
	endpoints    map[string]struct{}
	accessIDs    map[string]struct{}
	authMismatch map[string]struct{}
}

func Analyze(r io.Reader, opts Options) (Result, error) {
	window := opts.Window
	if window == 0 {
		window = 10 * time.Minute
	}

	stats := Stats{}
	seen := map[string]struct{}{}
	eventsByIP := map[string][]parsedEvent{}
	eventsByAccount := map[string][]parsedEvent{}
	var maxTime time.Time

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		stats.Read++
		var event normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			stats.Malformed++
			continue
		}
		if event.EventID == "" || event.Timestamp == "" || event.Subject == nil {
			stats.Skipped++
			continue
		}
		if _, ok := seen[event.EventID]; ok {
			stats.Duplicate++
			continue
		}
		seen[event.EventID] = struct{}{}

		timestamp, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err != nil {
			stats.Skipped++
			continue
		}
		ip, ok := event.Subject["ip"].(string)
		if !ok || ip == "" {
			stats.Skipped++
			continue
		}

		stats.Accepted++
		if maxTime.IsZero() || timestamp.After(maxTime) {
			maxTime = timestamp
		}
		eventsByIP[ip] = append(eventsByIP[ip], parsedEvent{Event: event, Time: timestamp})
		if accountID := subjectString(event, "account_id"); accountID != "" {
			eventsByAccount[accountID] = append(eventsByAccount[accountID], parsedEvent{Event: event, Time: timestamp})
		}
	}
	if err := scanner.Err(); err != nil {
		return Result{}, fmt.Errorf("read normalized input: %w", err)
	}

	result := Result{Stats: stats, Evidence: []Evidence{}}
	if !maxTime.IsZero() {
		result.MaxTime = maxTime.Format(time.RFC3339Nano)
	}
	cutoff := maxTime.Add(-window)

	ips := sortedKeys(eventsByIP)
	for _, ip := range ips {
		signals := newIPSignals()
		for _, parsed := range eventsByIP[ip] {
			if parsed.Time.Before(cutoff) {
				continue
			}
			signals.add(parsed.Event)
		}
		result.Evidence = append(result.Evidence, buildEvidence(ip, window, maxTime, signals)...)
	}
	accounts := sortedKeys(eventsByAccount)
	for _, accountID := range accounts {
		signals := newAccountSignals()
		for _, parsed := range eventsByAccount[accountID] {
			if parsed.Time.Before(cutoff) {
				continue
			}
			signals.add(parsed.Event)
		}
		result.Evidence = append(result.Evidence, buildAccountEvidence(accountID, window, maxTime, signals)...)
	}

	return result, nil
}

func AnalyzeFiles(inputPath, outputPath string, opts Options) (Result, error) {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return Result{}, err
	}
	defer closeInput()

	output, closeOutput, err := openOutput(outputPath)
	if err != nil {
		return Result{}, err
	}
	defer closeOutput()

	result, err := Analyze(input, opts)
	if err != nil {
		return Result{}, err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return Result{}, fmt.Errorf("write evidence result: %w", err)
	}
	return result, nil
}

func newIPSignals() ipSignals {
	return ipSignals{
		userAgents:          map[string]struct{}{},
		ja3:                 map[string]struct{}{},
		ja4:                 map[string]struct{}{},
		domains:             map[string]struct{}{},
		dstPorts:            map[string]struct{}{},
		deviceProfiles:      map[string]struct{}{},
		deviceFamilies:      map[string]struct{}{},
		vpnRuleMatches:      map[string]struct{}{},
		vpnDomainHints:      map[string]struct{}{},
		encryptedTransports: map[string]struct{}{},
	}
}

func newAccountSignals() accountSignals {
	return accountSignals{
		ips:          map[string]struct{}{},
		macs:         map[string]struct{}{},
		endpoints:    map[string]struct{}{},
		accessIDs:    map[string]struct{}{},
		authMismatch: map[string]struct{}{},
	}
}

func (s ipSignals) add(event normalized.Event) {
	if isInfrastructureRole(subjectString(event, "entity_role")) {
		return
	}
	addString(s.userAgents, event.Payload, "user_agent")
	addString(s.ja3, event.Payload, "ja3")
	addString(s.ja4, event.Payload, "ja4")
	addString(s.domains, event.Payload, "query")
	addString(s.domains, event.Payload, "sni")
	addString(s.domains, event.Payload, "host")
	addNumberString(s.dstPorts, event.Flow, "dst_port")
	s.addVPNSignals(event)
	if event.Type == "device" {
		s.addDevice(event.Payload)
	}
}

func (s ipSignals) addVPNSignals(event normalized.Event) {
	if event.Type == "alert" {
		if sample, ok := vpnAlertSample(event.Payload); ok {
			s.vpnRuleMatches[sample] = struct{}{}
		}
	}
	for _, key := range []string{"query", "sni", "host", "server_name"} {
		value := stringValue(event.Payload, key)
		if value == "" || !hasVPNHint(value) {
			continue
		}
		s.vpnDomainHints[key+":"+normalizeSample(value)] = struct{}{}
	}
	if event.Type == "quic" || isUDP443(event.Flow) {
		s.encryptedTransports[encryptedTransportSample(event)] = struct{}{}
	}
}

func (s ipSignals) addDevice(payload map[string]any) {
	if stringValue(payload, "origin") != "dhcp" {
		return
	}
	hostname := stringValue(payload, "hostname")
	vendorClass := stringValue(payload, "vendor_class")
	requestedOptions := stringValue(payload, "requested_options")
	clientMAC := stringValue(payload, "client_mac")
	hint := deviceFamily(payload)
	if hostname == "" && vendorClass == "" && requestedOptions == "" && clientMAC == "" && hint == "unknown" {
		return
	}
	profile := fmt.Sprintf("dhcp:%s:host=%s:vendor=%s:opts=%s:mac=%s",
		hint,
		normalizeSample(hostname),
		normalizeSample(vendorClass),
		normalizeSample(requestedOptions),
		normalizeSample(clientMAC),
	)
	s.deviceProfiles[profile] = struct{}{}
	if hint != "unknown" {
		s.deviceFamilies[hint] = struct{}{}
	}
}

func (s accountSignals) add(event normalized.Event) {
	role := subjectString(event, "entity_role")
	if isInfrastructureRole(role) || role == "unknown" {
		return
	}
	addSet(s.ips, subjectString(event, "ip"))
	addSet(s.macs, normalizeMAC(subjectString(event, "mac")))
	addSet(s.endpoints, subjectString(event, "endpoint_id"))
	addSet(s.accessIDs, subjectString(event, "access_id"))
	authMAC := normalizeMAC(stringValue(event.Payload, "auth_mac"))
	observedMAC := normalizeMAC(stringValue(event.Payload, "observed_mac"))
	if authMAC != "" && observedMAC != "" && authMAC != observedMAC {
		s.authMismatch[authMAC+" != "+observedMAC] = struct{}{}
	}
}

func buildEvidence(ip string, window time.Duration, createdAt time.Time, signals ipSignals) []Evidence {
	var output []Evidence
	windowText := window.String()
	createdAtText := createdAt.Format(time.RFC3339Nano)

	vpnRuleMatches := sortedSet(signals.vpnRuleMatches)
	if len(vpnRuleMatches) > 0 {
		score := cappedScore(68+len(vpnRuleMatches)*4, 78)
		output = append(output, newEvidence(ip, "vpn_proxy_rule_match", windowText, score, 0.92, "high",
			fmt.Sprintf("%s 内 Suricata 命中明确代理/VPN/隧道规则，属于翻墙监测高置信证据；仍以影子复核为准", windowText),
			limitSamples(vpnRuleMatches, 8), createdAtText))
	}

	vpnDomainHints := sortedSet(signals.vpnDomainHints)
	if len(vpnDomainHints) > 0 {
		score := cappedScore(30+len(vpnDomainHints)*4, 48)
		output = append(output, newEvidence(ip, "vpn_proxy_domain_hint", windowText, score, 0.68, "medium",
			fmt.Sprintf("%s 内域名/SNI/Host 出现代理、VPN 或隧道关键词，属于中置信线索，需要结合规则命中和账号行为复核", windowText),
			limitSamples(vpnDomainHints, 8), createdAtText))
	}

	encryptedTransports := sortedSet(signals.encryptedTransports)
	if len(encryptedTransports) > 0 {
		score := cappedScore(14+len(encryptedTransports)*2, 25)
		output = append(output, newEvidence(ip, "encrypted_tunnel_behavior", windowText, score, 0.45, "low",
			fmt.Sprintf("%s 内出现 QUIC 或 UDP/443 加密传输行为；这是低置信评分特征，不能单独定性为翻墙或代理", windowText),
			limitSamples(encryptedTransports, 8), createdAtText))
	}

	userAgents := sortedSet(signals.userAgents)
	if len(userAgents) >= 2 {
		score := cappedScore(10+len(userAgents)*3, 22)
		output = append(output, newEvidence(ip, "multi_user_agent", windowText, score, 0.35, severity(score),
			fmt.Sprintf("%s 内出现 %d 个不同 User-Agent；UA 可伪造，仅作为弱信号，需要结合 JA3/JA4、DHCP/OUI 或 TCP 指纹复核", windowText, len(userAgents)),
			limitSamples(userAgents, 5), createdAtText))
	}

	fingerprints := append(prefixSamples("ja3:", sortedSet(signals.ja3)), prefixSamples("ja4:", sortedSet(signals.ja4))...)
	sort.Strings(fingerprints)
	if len(fingerprints) >= 2 {
		score := cappedScore(15+len(fingerprints)*4, 30)
		output = append(output, newEvidence(ip, "multi_ja3_ja4", windowText, score, confidence(len(fingerprints)), severity(score),
			fmt.Sprintf("%s 内出现 %d 个不同 TLS 指纹，可能对应多客户端栈", windowText, len(fingerprints)),
			limitSamples(fingerprints, 5), createdAtText))
	}

	if len(userAgents) >= 2 && len(fingerprints) >= 2 {
		samples := append(limitSamples(userAgents, 3), limitSamples(fingerprints, 4)...)
		score := cappedScore(24+len(fingerprints)*4, 42)
		output = append(output, newEvidence(ip, "device_signal_conflict", windowText, score, 0.68, severity(score),
			fmt.Sprintf("%s 内 UA 弱信号与 TLS 指纹中信号同时出现多样性，疑似存在多客户端栈；仍需强设备信号确认", windowText),
			samples, createdAtText))
	}

	deviceProfiles := sortedSet(signals.deviceProfiles)
	if len(deviceProfiles) >= 1 {
		score := cappedScore(28+len(deviceProfiles)*3, 40)
		output = append(output, newEvidence(ip, "dhcp_device_fingerprint", windowText, score, 0.82, severity(score),
			fmt.Sprintf("%s 内从 DHCP 观察到设备画像；该信号来自局域网协议栈，可信度高于 User-Agent", windowText),
			limitSamples(deviceProfiles, 5), createdAtText))
	}

	deviceFamilies := sortedSet(signals.deviceFamilies)
	if len(deviceFamilies) >= 2 {
		samples := append(prefixSamples("family:", deviceFamilies), limitSamples(deviceProfiles, 5)...)
		score := cappedScore(42+len(deviceFamilies)*6, 58)
		output = append(output, newEvidence(ip, "device_fingerprint_conflict", windowText, score, 0.88, severity(score),
			fmt.Sprintf("%s 内同一 IP 出现 %d 类互斥 DHCP 设备画像，疑似共享上网或代理出口", windowText, len(deviceFamilies)),
			limitSamples(samples, 8), createdAtText))
	} else if len(deviceProfiles) >= 1 && len(fingerprints) >= 2 {
		samples := append(limitSamples(deviceProfiles, 4), limitSamples(fingerprints, 4)...)
		score := cappedScore(34+len(fingerprints)*3, 48)
		output = append(output, newEvidence(ip, "device_fingerprint_conflict", windowText, score, 0.78, severity(score),
			fmt.Sprintf("%s 内 DHCP 设备画像与多个 TLS 客户端指纹同时出现，需要按多设备出口复核", windowText),
			limitSamples(samples, 8), createdAtText))
	}

	domains := sortedSet(signals.domains)
	if len(domains) >= 20 {
		score := cappedScore(10+len(domains)/4, 25)
		output = append(output, newEvidence(ip, "domain_diversity", windowText, score, 0.65, severity(score),
			fmt.Sprintf("%s 内出现 %d 个不同 DNS/SNI/HTTP Host，域名多样性偏高", windowText, len(domains)),
			limitSamples(domains, 5), createdAtText))
	}

	dstPorts := sortedSet(signals.dstPorts)
	if len(dstPorts) >= 5 {
		score := cappedScore(10+len(dstPorts)*2, 25)
		output = append(output, newEvidence(ip, "port_distribution", windowText, score, 0.65, severity(score),
			fmt.Sprintf("%s 内访问 %d 个不同目的端口，连接模式需要结合其他证据判断", windowText, len(dstPorts)),
			limitSamples(dstPorts, 5), createdAtText))
	}

	return output
}

func buildAccountEvidence(accountID string, window time.Duration, createdAt time.Time, signals accountSignals) []Evidence {
	var output []Evidence
	windowText := window.String()
	createdAtText := createdAt.Format(time.RFC3339Nano)
	macs := sortedSet(signals.macs)
	endpoints := sortedSet(signals.endpoints)
	accessIDs := sortedSet(signals.accessIDs)
	if len(macs) >= 2 {
		score := cappedScore(58+len(macs)*6, 76)
		output = append(output, newSubjectEvidence("account", accountID, "", "account_concurrent_macs", windowText, score, 0.92, severity(score),
			fmt.Sprintf("%s 内同一账号关联 %d 个 endpoint MAC，属于防共享高置信证据", windowText, len(macs)),
			limitSamples(macs, 8), createdAtText))
	}
	if len(endpoints) >= 2 && len(macs) < 2 {
		score := cappedScore(52+len(endpoints)*5, 68)
		output = append(output, newSubjectEvidence("account", accountID, "", "account_concurrent_endpoints", windowText, score, 0.86, severity(score),
			fmt.Sprintf("%s 内同一账号关联 %d 个终端实体，需要复核是否账号共享或换机重认证", windowText, len(endpoints)),
			limitSamples(endpoints, 8), createdAtText))
	}
	if len(accessIDs) >= 2 {
		score := cappedScore(44+len(accessIDs)*6, 64)
		output = append(output, newSubjectEvidence("account", accountID, "", "account_concurrent_access", windowText, score, 0.82, severity(score),
			fmt.Sprintf("%s 内同一账号出现在 %d 个接入位置，需要排除漫游切换和日志延迟", windowText, len(accessIDs)),
			limitSamples(accessIDs, 8), createdAtText))
	}
	mismatches := sortedSet(signals.authMismatch)
	if len(mismatches) > 0 {
		score := cappedScore(62+len(mismatches)*4, 78)
		output = append(output, newSubjectEvidence("account", accountID, "", "auth_observed_mac_mismatch", windowText, score, 0.9, severity(score),
			fmt.Sprintf("%s 内认证 MAC 与实际观测 MAC 不一致，属于强复核证据", windowText),
			limitSamples(mismatches, 8), createdAtText))
	}
	return output
}

func newEvidence(ip, evidenceType, window string, score int, conf float64, severityText, reason string, samples []string, createdAt string) Evidence {
	item := Evidence{
		EvidenceID:  evidenceID(ip, evidenceType, window, createdAt, samples),
		IP:          ip,
		SubjectType: "ip",
		SubjectID:   ip,
		Type:        evidenceType,
		Window:      window,
		Score:       score,
		Confidence:  conf,
		Severity:    severityText,
		Reason:      reason,
		Samples:     samples,
		CreatedAt:   createdAt,
	}
	return item
}

func newSubjectEvidence(subjectType, subjectID, ip, evidenceType, window string, score int, conf float64, severityText, reason string, samples []string, createdAt string) Evidence {
	item := Evidence{
		EvidenceID:  evidenceID(subjectType+":"+subjectID, evidenceType, window, createdAt, samples),
		IP:          ip,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Type:        evidenceType,
		Window:      window,
		Score:       score,
		Confidence:  conf,
		Severity:    severityText,
		Reason:      reason,
		Samples:     samples,
		CreatedAt:   createdAt,
	}
	if subjectType == "account" {
		item.AccountID = subjectID
	}
	if subjectType == "endpoint" {
		item.EndpointID = subjectID
	}
	return item
}

func evidenceID(ip, evidenceType, window, createdAt string, samples []string) string {
	sum := sha256.Sum256([]byte(strings.Join(append([]string{ip, evidenceType, window, createdAt}, samples...), "|")))
	return "evidence-" + hex.EncodeToString(sum[:])[:20]
}

func cappedScore(score, maxScore int) int {
	if score > maxScore {
		return maxScore
	}
	return score
}

func confidence(count int) float64 {
	switch {
	case count >= 5:
		return 0.85
	case count >= 3:
		return 0.75
	default:
		return 0.65
	}
}

func severity(score int) string {
	switch {
	case score >= 35:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

func addString(set map[string]struct{}, fields map[string]any, key string) {
	if value, ok := fields[key].(string); ok && value != "" {
		set[value] = struct{}{}
	}
}

func addSet(set map[string]struct{}, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		set[value] = struct{}{}
	}
}

func stringValue(fields map[string]any, key string) string {
	if value, ok := fields[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func subjectString(event normalized.Event, key string) string {
	return stringValue(event.Subject, key)
}

func normalizeMAC(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, "-", ":")
	value = strings.ReplaceAll(value, ".", "")
	if len(value) == 12 && !strings.Contains(value, ":") {
		parts := []string{}
		for i := 0; i < 12; i += 2 {
			parts = append(parts, value[i:i+2])
		}
		value = strings.Join(parts, ":")
	}
	return value
}

func isInfrastructureRole(role string) bool {
	switch role {
	case "infrastructure", "gateway", "nat", "server", "network_device":
		return true
	default:
		return false
	}
}

func deviceFamily(fields map[string]any) string {
	text := strings.ToLower(strings.Join([]string{
		stringValue(fields, "device_hint"),
		stringValue(fields, "hostname"),
		stringValue(fields, "vendor_class"),
		stringValue(fields, "client_fqdn"),
	}, " "))
	switch {
	case strings.Contains(text, "iphone"), strings.Contains(text, "ipad"), strings.Contains(text, "ios"), strings.Contains(text, "apple"), strings.Contains(text, "macbook"), strings.Contains(text, "imac"):
		return "apple"
	case strings.Contains(text, "android"):
		return "android"
	case strings.Contains(text, "windows"), strings.Contains(text, "microsoft"), strings.Contains(text, "msft"):
		return "windows"
	case strings.Contains(text, "chromebook"), strings.Contains(text, "chromeos"):
		return "chromeos"
	case strings.Contains(text, "linux"), strings.Contains(text, "dhcpcd"), strings.Contains(text, "ubuntu"), strings.Contains(text, "debian"):
		return "linux"
	default:
		return "unknown"
	}
}

func normalizeSample(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if len(value) > 80 {
		return value[:80]
	}
	return value
}

func addNumberString(set map[string]struct{}, fields map[string]any, key string) {
	value, ok := fields[key]
	if !ok {
		return
	}
	switch typed := value.(type) {
	case float64:
		set[fmt.Sprintf("%.0f", typed)] = struct{}{}
	case int:
		set[fmt.Sprintf("%d", typed)] = struct{}{}
	case int64:
		set[fmt.Sprintf("%d", typed)] = struct{}{}
	case json.Number:
		set[typed.String()] = struct{}{}
	}
}

func numberString(fields map[string]any, key string) string {
	value, ok := fields[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case float64:
		return fmt.Sprintf("%.0f", typed)
	case int:
		return fmt.Sprintf("%d", typed)
	case int64:
		return fmt.Sprintf("%d", typed)
	case json.Number:
		return typed.String()
	case string:
		return strings.TrimSpace(typed)
	default:
		return ""
	}
}

func vpnAlertSample(payload map[string]any) (string, bool) {
	signature := stringValue(payload, "signature")
	category := stringValue(payload, "category")
	action := stringValue(payload, "action")
	text := strings.Join([]string{signature, category, action, metadataText(payload["metadata"])}, " ")
	if !HasVPNHint(text) {
		return "", false
	}
	parts := []string{}
	if sid := numberString(payload, "signature_id"); sid != "" {
		parts = append(parts, "sid:"+sid)
	}
	if signature != "" {
		parts = append(parts, "signature:"+normalizeSample(signature))
	}
	if category != "" {
		parts = append(parts, "category:"+normalizeSample(category))
	}
	if severity := numberString(payload, "severity"); severity != "" {
		parts = append(parts, "severity:"+severity)
	}
	if len(parts) == 0 {
		return "suricata-alert:vpn-proxy-tunnel", true
	}
	return strings.Join(parts, " "), true
}

// IsVPNAlert reports whether a normalized alert payload is an explicit
// proxy/VPN/tunnel rule match.
func IsVPNAlert(payload map[string]any) bool {
	_, ok := vpnAlertSample(payload)
	return ok
}

func metadataText(value any) string {
	if value == nil {
		return ""
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(data)
}

func hasVPNHint(value string) bool {
	return HasVPNHint(value)
}

// HasVPNHint reports whether normalized text contains an explicit proxy, VPN,
// tunnel, or circumvention marker. Store and presentation aggregations reuse
// this classifier so review views cannot silently drift from evidence rules.
func HasVPNHint(value string) bool {
	text := strings.ToLower(value)
	for _, keyword := range []string{
		"proxy", "vpn", "tunnel", "tunneling", "circumvention", "tor",
		"openvpn", "wireguard", "ipsec", "l2tp", "pptp", "gre", "teredo",
		"socks", "shadowsocks", "v2ray", "vmess", "trojan", "clash",
		"hysteria", "sing-box", "xray", "naiveproxy",
	} {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

func isUDP443(flow map[string]any) bool {
	if strings.ToLower(stringValue(flow, "proto")) != "udp" {
		return false
	}
	return numberString(flow, "dst_port") == "443"
}

func encryptedTransportSample(event normalized.Event) string {
	parts := []string{}
	if event.Type == "quic" {
		parts = append(parts, "type:quic")
	}
	if proto := stringValue(event.Flow, "proto"); proto != "" {
		parts = append(parts, "proto:"+strings.ToLower(proto))
	}
	if dst := stringValue(event.Flow, "dst_ip"); dst != "" {
		parts = append(parts, "dst:"+dst)
	}
	if port := numberString(event.Flow, "dst_port"); port != "" {
		parts = append(parts, "port:"+port)
	}
	if sni := stringValue(event.Payload, "sni"); sni != "" {
		parts = append(parts, "sni:"+normalizeSample(sni))
	}
	if alpn := stringValue(event.Payload, "alpn"); alpn != "" {
		parts = append(parts, "alpn:"+normalizeSample(alpn))
	}
	if len(parts) == 0 {
		return "encrypted-transport"
	}
	return strings.Join(parts, " ")
}

func sortedSet(set map[string]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func prefixSamples(prefix string, values []string) []string {
	output := make([]string, 0, len(values))
	for _, value := range values {
		output = append(output, prefix+value)
	}
	return output
}

func limitSamples(samples []string, limit int) []string {
	if len(samples) <= limit {
		return samples
	}
	return samples[:limit]
}

func openInput(path string) (io.Reader, func() error, error) {
	if path == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open input: %w", err)
	}
	return file, file.Close, nil
}

func openOutput(path string) (io.Writer, func() error, error) {
	if path == "-" || path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output: %w", err)
	}
	return file, file.Close, nil
}
