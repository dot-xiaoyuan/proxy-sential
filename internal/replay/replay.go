package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"proxy-sentinel/internal/normalized"
)

type Options struct {
	Windows []time.Duration
}

type Stats struct {
	Read      int `json:"read"`
	Accepted  int `json:"accepted"`
	Duplicate int `json:"duplicate"`
	Skipped   int `json:"skipped"`
	Malformed int `json:"malformed"`
}

type Summary struct {
	Stats   Stats       `json:"stats"`
	MaxTime string      `json:"max_time,omitempty"`
	Windows []IPWindows `json:"windows"`
}

type IPWindows struct {
	IP      string          `json:"ip"`
	Windows []WindowSummary `json:"windows"`
}

type WindowSummary struct {
	Window         string         `json:"window"`
	EventCount     int            `json:"event_count"`
	ByType         map[string]int `json:"by_type,omitempty"`
	DomainCount    int            `json:"domain_count"`
	UserAgentCount int            `json:"user_agent_count"`
	JA3Count       int            `json:"ja3_count"`
	JA4Count       int            `json:"ja4_count"`
	DstPortCount   int            `json:"dst_port_count"`
}

type parsedEvent struct {
	Event normalized.Event
	Time  time.Time
	IP    string
}

type accumulator struct {
	eventCount int
	byType     map[string]int
	domains    map[string]struct{}
	userAgents map[string]struct{}
	ja3        map[string]struct{}
	ja4        map[string]struct{}
	dstPorts   map[string]struct{}
}

func Analyze(r io.Reader, opts Options) (Summary, error) {
	windows := opts.Windows
	if len(windows) == 0 {
		windows = []time.Duration{time.Minute, 5 * time.Minute, 10 * time.Minute, time.Hour}
	}

	stats := Stats{}
	seen := map[string]struct{}{}
	eventsByIP := map[string][]parsedEvent{}
	var maxTime time.Time

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		stats.Read++
		line := scanner.Bytes()
		var event normalized.Event
		if err := json.Unmarshal(line, &event); err != nil {
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
		eventsByIP[ip] = append(eventsByIP[ip], parsedEvent{Event: event, Time: timestamp, IP: ip})
	}
	if err := scanner.Err(); err != nil {
		return Summary{}, fmt.Errorf("read normalized input: %w", err)
	}

	ips := make([]string, 0, len(eventsByIP))
	for ip := range eventsByIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	summary := Summary{Stats: stats}
	if !maxTime.IsZero() {
		summary.MaxTime = maxTime.Format(time.RFC3339Nano)
	}
	for _, ip := range ips {
		ipWindows := IPWindows{IP: ip}
		for _, window := range windows {
			acc := newAccumulator()
			cutoff := maxTime.Add(-window)
			for _, event := range eventsByIP[ip] {
				if event.Time.Before(cutoff) {
					continue
				}
				acc.add(event.Event)
			}
			ipWindows.Windows = append(ipWindows.Windows, acc.summary(window))
		}
		summary.Windows = append(summary.Windows, ipWindows)
	}

	return summary, nil
}

func AnalyzeFiles(inputPath, outputPath string, opts Options) (Summary, error) {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return Summary{}, err
	}
	defer closeInput()

	output, closeOutput, err := openOutput(outputPath)
	if err != nil {
		return Summary{}, err
	}
	defer closeOutput()

	summary, err := Analyze(input, opts)
	if err != nil {
		return Summary{}, err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return Summary{}, fmt.Errorf("write replay summary: %w", err)
	}
	return summary, nil
}

func newAccumulator() accumulator {
	return accumulator{
		byType:     map[string]int{},
		domains:    map[string]struct{}{},
		userAgents: map[string]struct{}{},
		ja3:        map[string]struct{}{},
		ja4:        map[string]struct{}{},
		dstPorts:   map[string]struct{}{},
	}
}

func (a *accumulator) add(event normalized.Event) {
	a.eventCount++
	a.byType[event.Type]++
	addString(a.domains, event.Payload, "query")
	addString(a.domains, event.Payload, "sni")
	addString(a.domains, event.Payload, "host")
	addString(a.userAgents, event.Payload, "user_agent")
	addString(a.ja3, event.Payload, "ja3")
	addString(a.ja4, event.Payload, "ja4")
	addNumberString(a.dstPorts, event.Flow, "dst_port")
}

func (a accumulator) summary(window time.Duration) WindowSummary {
	return WindowSummary{
		Window:         window.String(),
		EventCount:     a.eventCount,
		ByType:         a.byType,
		DomainCount:    len(a.domains),
		UserAgentCount: len(a.userAgents),
		JA3Count:       len(a.ja3),
		JA4Count:       len(a.ja4),
		DstPortCount:   len(a.dstPorts),
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
