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
	EvidenceID string   `json:"evidence_id"`
	IP         string   `json:"ip"`
	Type       string   `json:"type"`
	Window     string   `json:"window"`
	Score      int      `json:"score"`
	Confidence float64  `json:"confidence"`
	Severity   string   `json:"severity"`
	Reason     string   `json:"reason"`
	Samples    []string `json:"samples"`
	CreatedAt  string   `json:"created_at"`
}

type parsedEvent struct {
	Event normalized.Event
	Time  time.Time
}

type ipSignals struct {
	userAgents map[string]struct{}
	ja3        map[string]struct{}
	ja4        map[string]struct{}
	domains    map[string]struct{}
	dstPorts   map[string]struct{}
}

func Analyze(r io.Reader, opts Options) (Result, error) {
	window := opts.Window
	if window == 0 {
		window = 10 * time.Minute
	}

	stats := Stats{}
	seen := map[string]struct{}{}
	eventsByIP := map[string][]parsedEvent{}
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
	}
	if err := scanner.Err(); err != nil {
		return Result{}, fmt.Errorf("read normalized input: %w", err)
	}

	result := Result{Stats: stats}
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
		userAgents: map[string]struct{}{},
		ja3:        map[string]struct{}{},
		ja4:        map[string]struct{}{},
		domains:    map[string]struct{}{},
		dstPorts:   map[string]struct{}{},
	}
}

func (s ipSignals) add(event normalized.Event) {
	addString(s.userAgents, event.Payload, "user_agent")
	addString(s.ja3, event.Payload, "ja3")
	addString(s.ja4, event.Payload, "ja4")
	addString(s.domains, event.Payload, "query")
	addString(s.domains, event.Payload, "sni")
	addString(s.domains, event.Payload, "host")
	addNumberString(s.dstPorts, event.Flow, "dst_port")
}

func buildEvidence(ip string, window time.Duration, createdAt time.Time, signals ipSignals) []Evidence {
	var output []Evidence
	windowText := window.String()
	createdAtText := createdAt.Format(time.RFC3339Nano)

	userAgents := sortedSet(signals.userAgents)
	if len(userAgents) >= 2 {
		score := cappedScore(20+len(userAgents)*5, 35)
		output = append(output, newEvidence(ip, "multi_user_agent", windowText, score, confidence(len(userAgents)), severity(score),
			fmt.Sprintf("%s 内出现 %d 个不同 User-Agent，可能对应多设备或共享上网", windowText, len(userAgents)),
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

func newEvidence(ip, evidenceType, window string, score int, conf float64, severityText, reason string, samples []string, createdAt string) Evidence {
	return Evidence{
		EvidenceID: evidenceID(ip, evidenceType, window, createdAt, samples),
		IP:         ip,
		Type:       evidenceType,
		Window:     window,
		Score:      score,
		Confidence: conf,
		Severity:   severityText,
		Reason:     reason,
		Samples:    samples,
		CreatedAt:  createdAt,
	}
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
