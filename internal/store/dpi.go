package store

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

const defaultDPIEventLimit = 100000

type dpiIPSignals struct {
	ja       map[string]activityBucket
	ttl      map[string]activityBucket
	lastSeen string
}

func BuildDPIOverview(sensorID string, window string, events []normalized.Event, risks map[string]risk.Snapshot) DPIOverview {
	activity := BuildActivityOverview(sensorID, window, events, risks)
	conflicts := BuildDPIFingerprintConflicts(events, risks)
	protocols := BuildDPIProtocolFlows(events)
	return DPIOverview{
		SensorID:                 sensorID,
		Window:                   activity.Window,
		EventCount:               activity.EventCount,
		ActiveIPCount:            activity.ActiveIPCount,
		ProtocolFlowCount:        len(protocols),
		FingerprintConflictCount: len(conflicts),
		FlowSampleCount:          len(events),
		FirstSeen:                activity.FirstSeen,
		LastSeen:                 activity.LastSeen,
	}
}

func BuildDPITrends(window string, events []normalized.Event, risks map[string]risk.Snapshot) []DPITrendPoint {
	if len(events) == 0 {
		return []DPITrendPoint{}
	}
	bucketDuration := time.Minute
	if window == "24h" {
		bucketDuration = time.Hour
	}
	type trendBucket struct {
		events int
		ips    map[string]struct{}
		risks  map[string]struct{}
	}
	buckets := map[time.Time]*trendBucket{}
	for _, event := range events {
		ts, ok := parseTime(event.Timestamp)
		if !ok {
			continue
		}
		key := ts.Truncate(bucketDuration)
		bucket := buckets[key]
		if bucket == nil {
			bucket = &trendBucket{ips: map[string]struct{}{}, risks: map[string]struct{}{}}
			buckets[key] = bucket
		}
		bucket.events++
		ip := subjectIP(event)
		if ip != "" {
			bucket.ips[ip] = struct{}{}
			if snapshot, ok := risks[ip]; ok && snapshot.Level != "" && snapshot.Level != "normal" {
				bucket.risks[ip] = struct{}{}
			}
		}
	}
	keys := make([]time.Time, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
	result := make([]DPITrendPoint, 0, len(keys))
	seconds := bucketDuration.Seconds()
	for _, key := range keys {
		bucket := buckets[key]
		cps := float64(bucket.events) / seconds
		result = append(result, DPITrendPoint{
			Time:          key.Format(time.RFC3339),
			ActiveDevices: len(bucket.ips),
			RiskIPs:       len(bucket.risks),
			EventCount:    bucket.events,
			PPS:           nil,
			BPSMbps:       nil,
			CPS:           cps,
			Estimated:     true,
		})
	}
	return result
}

func BuildDPIProtocolFlows(events []normalized.Event) []DPIProtocolFlow {
	type protocolBucket struct {
		count int
		apps  map[string]int
	}
	buckets := map[string]*protocolBucket{}
	total := 0
	for _, event := range events {
		protocol := dpiProtocol(event)
		if protocol == "" {
			continue
		}
		total++
		bucket := buckets[protocol]
		if bucket == nil {
			bucket = &protocolBucket{apps: map[string]int{}}
			buckets[protocol] = bucket
		}
		bucket.count++
		app := dpiTarget(event)
		if app != "" {
			bucket.apps[app]++
		}
	}
	if total == 0 {
		return []DPIProtocolFlow{}
	}
	items := make([]DPIProtocolFlow, 0, len(buckets))
	for protocol, bucket := range buckets {
		items = append(items, DPIProtocolFlow{
			Protocol:     protocol,
			AppProtocol:  protocol,
			Category:     dpiCategory(protocol),
			SharePercent: float64(bucket.count) * 100 / float64(total),
			EventCount:   bucket.count,
			BPSMbps:      nil,
			TopApps:      topStringCounts(bucket.apps, 6),
			TopTargets:   topStringCounts(bucket.apps, 6),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].EventCount != items[j].EventCount {
			return items[i].EventCount > items[j].EventCount
		}
		return items[i].Protocol < items[j].Protocol
	})
	return items
}

func BuildDPIFingerprintConflicts(events []normalized.Event, risks map[string]risk.Snapshot) []DPIFingerprintConflict {
	signals := map[string]*dpiIPSignals{}
	for _, event := range events {
		ip := subjectIP(event)
		if ip == "" {
			continue
		}
		signal := signals[ip]
		if signal == nil {
			signal = &dpiIPSignals{
				ja:  map[string]activityBucket{},
				ttl: map[string]activityBucket{},
			}
			signals[ip] = signal
		}
		if event.Timestamp > signal.lastSeen {
			signal.lastSeen = event.Timestamp
		}
		increment(signal.ja, "ja3:"+stringFromMap(event.Payload, "ja3"), event.Timestamp)
		increment(signal.ja, "ja4:"+stringFromMap(event.Payload, "ja4"), event.Timestamp)
		if ttl := intFromMap(event.Flow, "ttl"); ttl > 0 {
			increment(signal.ttl, fmt.Sprintf("%d", ttl), event.Timestamp)
		}
	}
	items := []DPIFingerprintConflict{}
	for ip, signal := range signals {
		if len(signal.ja) >= 2 {
			items = append(items, dpiConflict(ip, "ja3_mismatch", "TLS 客户端栈差异", signal.ja, signal.lastSeen, risks[ip]))
		}
		if len(signal.ttl) >= 2 {
			items = append(items, dpiConflict(ip, "ttl_step", "网络栈 TTL 差异", signal.ttl, signal.lastSeen, risks[ip]))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].RiskLevel != items[j].RiskLevel {
			left, _ := levelRank(items[i].RiskLevel)
			right, _ := levelRank(items[j].RiskLevel)
			return left > right
		}
		if items[i].SampleCount != items[j].SampleCount {
			return items[i].SampleCount > items[j].SampleCount
		}
		return items[i].LastSeen > items[j].LastSeen
	})
	return items
}

func BuildDPIFlowSamples(events []normalized.Event) []DPIFlowSample {
	items := make([]DPIFlowSample, 0, len(events))
	for _, event := range events {
		items = append(items, dpiFlowSample(event))
	}
	return items
}

func BuildDPIFlowDetail(event normalized.Event, snapshot risk.Snapshot, evidenceItems []evidence.Evidence) DPIFlowDetail {
	return DPIFlowDetail{Flow: dpiFlowSample(event), Event: event, Risk: snapshot, Evidence: evidenceItems}
}

func dpiFlowSample(event normalized.Event) DPIFlowSample {
	ttl := optionalIntFromMap(event.Flow, "ttl")
	ipid := optionalIntFromMap(event.Flow, "ipid")
	return DPIFlowSample{
		FlowID:         event.EventID,
		EventID:        event.EventID,
		Timestamp:      event.Timestamp,
		SensorID:       stringFromMap(event.Observer, "sensor_id"),
		InterfaceName:  stringFromMap(event.Observer, "interface"),
		SrcIP:          stringFromMap(event.Flow, "src_ip"),
		SrcPort:        intFromMap(event.Flow, "src_port"),
		DstIP:          stringFromMap(event.Flow, "dst_ip"),
		DstPort:        intFromMap(event.Flow, "dst_port"),
		Protocol:       stringFromMap(event.Flow, "proto"),
		AppProtocol:    dpiProtocol(event),
		UserAgent:      stringFromMap(event.Payload, "user_agent"),
		TLSSNI:         stringFromMap(event.Payload, "sni"),
		Domain:         dpiTarget(event),
		JA3:            stringFromMap(event.Payload, "ja3"),
		JA4:            stringFromMap(event.Payload, "ja4"),
		TTL:            ttl,
		IPID:           ipid,
		PayloadSummary: dpiPayloadSummary(event),
	}
}

func dpiConflict(ip string, conflictType string, label string, samples map[string]activityBucket, lastSeen string, snapshot risk.Snapshot) DPIFingerprintConflict {
	riskLevel := snapshot.Level
	if riskLevel == "" {
		riskLevel = "normal"
	}
	sampleCount := len(samples)
	confidence := 0.55 + float64(sampleCount)*0.08
	if confidence > 0.95 {
		confidence = 0.95
	}
	reason := fmt.Sprintf("%s 在同一观测窗口内出现 %d 组网络客户端栈样本，需要结合身份会话、MAC 或 DHCP 证据复核", ip, sampleCount)
	return DPIFingerprintConflict{
		ID:              "dpi-conflict-" + shortHash(conflictType+"|"+ip+"|"+lastSeen),
		IP:              ip,
		ConflictType:    conflictType,
		TypeLabel:       label,
		RiskLevel:       riskLevel,
		Confidence:      confidence,
		SampleCount:     sampleCount,
		Scope:           "ip_window",
		SignalTypes:     []string{conflictType},
		Assessment:      "needs_corroboration",
		DetectedSamples: topActivityValues(samples, 8),
		Reason:          reason,
		LastSeen:        lastSeen,
	}
}

func dpiProtocol(event normalized.Event) string {
	switch event.Type {
	case "dns":
		return "DNS"
	case "http":
		return "HTTP"
	case "tls":
		return "TLS"
	case "quic":
		return "QUIC"
	case "flow":
		proto := strings.ToUpper(stringFromMap(event.Flow, "proto"))
		if proto != "" {
			return proto
		}
		return "FLOW"
	default:
		return strings.ToUpper(event.Type)
	}
}

func dpiCategory(protocol string) string {
	switch strings.ToUpper(protocol) {
	case "HTTP":
		return "Web/API"
	case "TLS", "QUIC":
		return "Encrypted Security"
	case "DNS":
		return "Core Infrastructure"
	default:
		return "Other"
	}
}

func dpiTarget(event normalized.Event) string {
	switch event.Type {
	case "dns":
		return stringFromMap(event.Payload, "query")
	case "http":
		return stringFromMap(event.Payload, "host")
	case "tls":
		return stringFromMap(event.Payload, "sni")
	default:
		if dst := stringFromMap(event.Flow, "dst_ip"); dst != "" {
			if port := intFromMap(event.Flow, "dst_port"); port > 0 {
				return fmt.Sprintf("%s:%d", dst, port)
			}
			return dst
		}
		return ""
	}
}

func dpiPayloadSummary(event normalized.Event) string {
	switch event.Type {
	case "dns":
		return "DNS query " + stringFromMap(event.Payload, "query")
	case "http":
		return strings.TrimSpace(stringFromMap(event.Payload, "method") + " " + stringFromMap(event.Payload, "host") + stringFromMap(event.Payload, "url"))
	case "tls":
		return "TLS SNI " + stringFromMap(event.Payload, "sni")
	default:
		return strings.TrimSpace(dpiProtocol(event) + " " + dpiTarget(event))
	}
}

func topActivityValues(buckets map[string]activityBucket, limit int) []string {
	counts := topActivityCounts(buckets, limit)
	values := make([]string, 0, len(counts))
	for _, count := range counts {
		values = append(values, count.Value)
	}
	return values
}

func topStringCounts(counts map[string]int, limit int) []string {
	type item struct {
		value string
		count int
	}
	items := make([]item, 0, len(counts))
	for value, count := range counts {
		items = append(items, item{value: value, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].value < items[j].value
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.value)
	}
	return result
}

func optionalIntFromMap(values map[string]any, key string) *int {
	value := intFromMap(values, key)
	if value == 0 {
		return nil
	}
	return &value
}

func shortHash(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}
