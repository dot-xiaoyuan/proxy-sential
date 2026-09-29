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

	"proxy-sentinel/internal/airelay"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"proxy-sentinel/internal/sharedaccess"
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
	SharedAccess  *sharedaccess.Window  `json:"shared_access,omitempty"`
	ProxyProtocol *proxyprotocol.Result `json:"proxy_protocol,omitempty"`
	EvidenceID    string                `json:"evidence_id"`
	IP            string                `json:"ip"`
	SubjectType   string                `json:"subject_type,omitempty"`
	SubjectID     string                `json:"subject_id,omitempty"`
	AccountID     string                `json:"account_id,omitempty"`
	EndpointID    string                `json:"endpoint_id,omitempty"`
	Type          string                `json:"type"`
	Window        string                `json:"window"`
	Score         int                   `json:"score"`
	Confidence    float64               `json:"confidence"`
	Severity      string                `json:"severity"`
	Reason        string                `json:"reason"`
	Samples       []string              `json:"samples"`
	CreatedAt     string                `json:"created_at"`
}

type parsedEvent struct {
	Event normalized.Event
	Time  time.Time
}

type ipSignals struct {
	userAgents          map[string]struct{}
	uaOSFamilies        map[string]struct{}
	ja3                 map[string]struct{}
	ja4                 map[string]struct{}
	domains             map[string]struct{}
	dstPorts            map[string]struct{}
	deviceProfiles      map[string]struct{}
	deviceFamilies      map[string]struct{}
	vpnRuleMatches      map[string]struct{}
	vpnRuleHints        map[string]struct{}
	vpnDomainHints      map[string]struct{}
	encryptedTransports map[string]struct{}
	ttlClusters         map[string]struct{}
	tcpStacks           map[string]struct{}
	applications        map[string]struct{}
	aiRelayDomains      map[string]struct{}
	aiRelayConfidence   float64
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
		if event.Type == "discovery" {
			stats.Skipped++
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
		uaOSFamilies:        map[string]struct{}{},
		ja3:                 map[string]struct{}{},
		ja4:                 map[string]struct{}{},
		domains:             map[string]struct{}{},
		dstPorts:            map[string]struct{}{},
		deviceProfiles:      map[string]struct{}{},
		deviceFamilies:      map[string]struct{}{},
		vpnRuleMatches:      map[string]struct{}{},
		vpnRuleHints:        map[string]struct{}{},
		vpnDomainHints:      map[string]struct{}{},
		encryptedTransports: map[string]struct{}{},
		ttlClusters:         map[string]struct{}{},
		tcpStacks:           map[string]struct{}{},
		applications:        map[string]struct{}{},
		aiRelayDomains:      map[string]struct{}{},
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
	if family := userAgentOSFamily(stringValue(event.Payload, "user_agent")); family != "" {
		s.uaOSFamilies[family] = struct{}{}
	}
	addString(s.ja3, event.Payload, "ja3")
	addString(s.ja4, event.Payload, "ja4")
	addString(s.domains, event.Payload, "query")
	addString(s.domains, event.Payload, "sni")
	addString(s.domains, event.Payload, "host")
	addNumberString(s.dstPorts, event.Flow, "dst_port")
	s.addVPNSignals(event)
	s.addAIRelaySignals(event)
	s.addApplications(event)
	if event.Type == "device" {
		s.addDevice(event.Payload)
		s.addTTL(event)
		addString(s.tcpStacks, event.Payload, "tcp_stack")
	}
}

func (s ipSignals) addApplications(event normalized.Event) {
	values := []string{}
	for _, key := range []string{"application", "software_name", "user_agent", "host", "query", "sni"} {
		if value := stringValue(event.Payload, key); value != "" {
			values = append(values, value)
		}
	}
	for _, match := range fingerprint.MatchApplication(values...) {
		s.applications[fmt.Sprintf("%s|%s|%.2f|%s|%s", match.Name, match.Category, match.Confidence, match.Source, match.Version)] = struct{}{}
	}
}

func (s ipSignals) addTTL(event normalized.Event) {
	value, ok := numberValue(event.Payload["ttl"])
	if !ok || value < 1 || value > 255 {
		return
	}
	initial := 255
	for _, candidate := range []int{32, 64, 128, 255} {
		if value <= candidate {
			initial = candidate
			break
		}
	}
	hops := initial - value
	direction := stringValue(event.Flow, "direction")
	if direction == "" {
		direction = "unknown"
	}
	s.ttlClusters[fmt.Sprintf("direction=%s,initial=%d,hops=%d,observed=%d", direction, initial, hops, value)] = struct{}{}
}

func (s ipSignals) addVPNSignals(event normalized.Event) {
	if event.Type == "alert" {
		if sample, confidence, ok := vpnAlertSample(event.Payload); ok {
			if confidence == "high" {
				s.vpnRuleMatches[sample] = struct{}{}
			} else {
				s.vpnRuleHints[sample] = struct{}{}
			}
		}
	}
	for _, key := range []string{"query", "sni", "host", "server_name"} {
		value := stringValue(event.Payload, key)
		if value == "" || !hasVPNHint(value) || isInstitutionalVPNDomain(value) {
			continue
		}
		s.vpnDomainHints[key+":"+normalizeSample(value)] = struct{}{}
	}
	if event.Type == "quic" || isUDP443(event.Flow) {
		s.encryptedTransports[encryptedTransportSample(event)] = struct{}{}
	}
}

func (s ipSignals) addAIRelaySignals(event normalized.Event) {
	matcher := airelay.Default()
	for _, key := range []string{"query", "sni", "host", "server_name"} {
		value := stringValue(event.Payload, key)
		if value == "" {
			continue
		}
		indicator, ok := matcher.Match(value)
		if !ok {
			continue
		}
		name := indicator.Name
		if name == "" {
			name = indicator.Domain
		}
		s.aiRelayDomains[fmt.Sprintf("%s=%s|%s|%s|%.2f|%s", key, normalizeSample(value), name, indicator.Category, indicator.Confidence, indicator.Source)] = struct{}{}
		if indicator.Confidence > s.aiRelayConfidence {
			s.aiRelayConfidence = indicator.Confidence
		}
	}
}

func isInstitutionalVPNDomain(value string) bool {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if !strings.HasSuffix(host, ".edu.cn") {
		return false
	}
	first := strings.SplitN(host, ".", 2)[0]
	return first == "vpn" || first == "webvpn" || first == "sslvpn"
}

func userAgentOSFamily(value string) string {
	text := strings.ToLower(value)
	switch {
	case strings.Contains(text, "android"):
		return "Android"
	case strings.Contains(text, "iphone") || strings.Contains(text, "ipad"):
		return "iOS/iPadOS"
	case strings.Contains(text, "windows nt"):
		return "Windows"
	case strings.Contains(text, "cros"):
		return "ChromeOS"
	case strings.Contains(text, "macintosh") || strings.Contains(text, "mac os x"):
		return "macOS"
	default:
		return ""
	}
}

func (s ipSignals) addDevice(payload map[string]any) {
	origin := stringValue(payload, "origin")
	if origin != "dhcp" && origin != "mdns" && origin != "nbns" && origin != "llmnr" {
		return
	}
	hostname := firstString(payload, "hostname", "device_name", "query")
	vendorClass := stringValue(payload, "vendor_class")
	requestedOptions := stringValue(payload, "requested_options")
	clientMAC := stringValue(payload, "client_mac")
	hint := deviceFamily(payload)
	if hostname == "" && vendorClass == "" && requestedOptions == "" && clientMAC == "" && hint == "unknown" {
		return
	}
	profile := fmt.Sprintf("%s:%s:host=%s:vendor=%s:opts=%s:mac=%s",
		origin,
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
	applications := sortedSet(signals.applications)
	if len(applications) > 0 {
		output = append(output, newEvidence(ip, "known_game_accelerator", windowText, 0, 0.82, "info", fmt.Sprintf("%s 内识别到已知游戏加速器；仅作为误报抑制和人工解释，不作为代理处罚证据", windowText), limitSamples(applications, 5), createdAtText))
	}
	uaOSFamilies := sortedSet(signals.uaOSFamilies)
	if len(uaOSFamilies) >= 2 {
		score := cappedScore(18+len(uaOSFamilies)*5, 35)
		output = append(output, newEvidence(ip, "ua_os_divergence", windowText, score, 0.65, "low",
			fmt.Sprintf("%s 内 User-Agent 明确呈现 %d 类互异操作系统；该派生信号必须与 TTL、TLS 或设备协议栈共同使用", windowText, len(uaOSFamilies)),
			limitSamples(uaOSFamilies, 8), createdAtText))
	}

	vpnRuleMatches := sortedSet(signals.vpnRuleMatches)
	if len(vpnRuleMatches) > 0 {
		score := cappedScore(68+len(vpnRuleMatches)*4, 78)
		output = append(output, newEvidence(ip, "vpn_proxy_rule_match", windowText, score, 0.92, "high",
			fmt.Sprintf("%s 内 Suricata 命中明确代理/VPN/隧道规则，属于翻墙监测高置信证据；仍以影子复核为准", windowText),
			limitSamples(vpnRuleMatches, 8), createdAtText))
	}

	vpnRuleHints := sortedSet(signals.vpnRuleHints)
	if len(vpnRuleHints) > 0 {
		score := cappedScore(24+len(vpnRuleHints)*3, 40)
		output = append(output, newEvidence(ip, "vpn_proxy_rule_hint", windowText, score, 0.65, "medium",
			fmt.Sprintf("%s 内 Suricata 命中中置信代理线索；端口、CONNECT、SOCKS 或关键词不能单独确认代理", windowText),
			limitSamples(vpnRuleHints, 8), createdAtText))
	}

	vpnDomainHints := sortedSet(signals.vpnDomainHints)
	if len(vpnDomainHints) > 0 {
		score := cappedScore(30+len(vpnDomainHints)*4, 48)
		output = append(output, newEvidence(ip, "vpn_proxy_domain_hint", windowText, score, 0.68, "medium",
			fmt.Sprintf("%s 内域名/SNI/Host 出现代理、VPN 或隧道关键词，属于中置信线索，需要结合规则命中和账号行为复核", windowText),
			limitSamples(vpnDomainHints, 8), createdAtText))
	}

	aiRelayDomains := sortedSet(signals.aiRelayDomains)
	if len(aiRelayDomains) > 0 {
		score := cappedScore(26+len(aiRelayDomains)*4, 42)
		relayConfidence := signals.aiRelayConfidence
		if relayConfidence <= 0 || relayConfidence > 0.85 {
			relayConfidence = 0.72
		}
		output = append(output, newEvidence(ip, "ai_relay_domain_usage", windowText, score, relayConfidence, severity(score),
			fmt.Sprintf("%s 内 DNS/SNI/Host 命中 %d 条已知 AI API 中转站域名；仅证明访问了中转站域名，需结合账号与实际调用行为人工复核", windowText, len(aiRelayDomains)),
			limitSamples(aiRelayDomains, 8), createdAtText))
	}

	encryptedTransports := sortedSet(signals.encryptedTransports)
	if len(encryptedTransports) > 0 {
		score := cappedScore(14+len(encryptedTransports)*2, 25)
		output = append(output, newEvidence(ip, "encrypted_tunnel_behavior", windowText, score, 0.45, "low",
			fmt.Sprintf("%s 内出现 QUIC 或 UDP/443 加密传输行为；这是低置信评分特征，不能单独定性为翻墙或代理", windowText),
			limitSamples(encryptedTransports, 8), createdAtText))
	}

	fingerprints := append(prefixSamples("ja3:", sortedSet(signals.ja3)), prefixSamples("ja4:", sortedSet(signals.ja4))...)
	sort.Strings(fingerprints)
	if len(fingerprints) >= 2 {
		score := cappedScore(15+len(fingerprints)*4, 30)
		output = append(output, newEvidence(ip, "multi_ja3_ja4", windowText, score, confidence(len(fingerprints)), severity(score),
			fmt.Sprintf("%s 内出现 %d 个不同 TLS 指纹，可能对应多客户端栈", windowText, len(fingerprints)),
			limitSamples(fingerprints, 5), createdAtText))
	}

	deviceProfiles := sortedSet(signals.deviceProfiles)
	if len(deviceProfiles) >= 1 {
		output = append(output, newEvidence(ip, "dhcp_device_fingerprint", windowText, 0, 0.82, "info",
			fmt.Sprintf("%s 内从 DHCP/mDNS/NBNS/LLMNR 观察到设备画像；单一正常画像仅用于解释，不增加风险分", windowText),
			limitSamples(deviceProfiles, 5), createdAtText))
	}

	deviceFamilies := sortedSet(signals.deviceFamilies)
	if len(deviceFamilies) >= 2 {
		samples := append(prefixSamples("family:", deviceFamilies), limitSamples(deviceProfiles, 5)...)
		score := cappedScore(42+len(deviceFamilies)*6, 58)
		output = append(output, newEvidence(ip, "device_fingerprint_conflict", windowText, score, 0.88, severity(score),
			fmt.Sprintf("%s 内同一 IP 出现 %d 类互斥局域网设备画像，疑似共享上网或代理出口", windowText, len(deviceFamilies)),
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

	ttlClusters := repeatedDirectionTTLClusters(sortedSet(signals.ttlClusters))
	if len(ttlClusters) >= 2 {
		score := cappedScore(18+len(ttlClusters)*3, 30)
		output = append(output, newEvidence(ip, "ttl_clusters", windowText, score, 0.68, "low",
			fmt.Sprintf("%s 内观察到 %d 个归一化 TTL 路径簇；该信号可能受路由变化影响，不能单独确认共享上网", windowText, len(ttlClusters)),
			limitSamples(ttlClusters, 6), createdAtText))
	}

	return output
}

func repeatedDirectionTTLClusters(clusters []string) []string {
	byDirection := map[string][]string{}
	for _, cluster := range clusters {
		direction := strings.SplitN(cluster, ",", 2)[0]
		byDirection[direction] = append(byDirection[direction], cluster)
	}
	result := []string{}
	for _, items := range byDirection {
		if len(items) >= 2 {
			result = append(result, items...)
		}
	}
	sort.Strings(result)
	return result
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

func firstString(fields map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(fields, key); value != "" {
			return value
		}
	}
	return ""
}

func numberValue(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	case json.Number:
		parsed, err := typed.Int64()
		return int(parsed), err == nil
	case string:
		var parsed int
		_, err := fmt.Sscanf(strings.TrimSpace(typed), "%d", &parsed)
		return parsed, err == nil
	default:
		return 0, false
	}
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
		stringValue(fields, "device_name"),
		stringValue(fields, "query"),
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

func vpnAlertSample(payload map[string]any) (string, string, bool) {
	signature := stringValue(payload, "signature")
	category := stringValue(payload, "category")
	action := stringValue(payload, "action")
	text := strings.Join([]string{signature, category, action, metadataText(payload["metadata"])}, " ")
	if !HasVPNHint(text) {
		return "", "", false
	}
	confidence := ruleConfidence(payload["metadata"])
	if confidence == "" {
		confidence = "medium"
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
		return "suricata-alert:vpn-proxy-tunnel", confidence, true
	}
	return strings.Join(parts, " "), confidence, true
}

func ruleConfidence(metadata any) string {
	text := strings.ToLower(metadataText(metadata))
	for _, candidate := range []string{"high", "medium"} {
		for _, marker := range []string{"proxy_sentinel_confidence " + candidate, "proxy_sentinel_confidence=" + candidate, "proxy-sentinel-confidence " + candidate, `proxy_sentinel_confidence":["` + candidate} {
			if strings.Contains(text, marker) {
				return candidate
			}
		}
	}
	return ""
}

// IsVPNAlert reports whether a normalized alert payload is an explicit
// proxy/VPN/tunnel rule match.
func IsVPNAlert(payload map[string]any) bool {
	_, _, ok := vpnAlertSample(payload)
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
