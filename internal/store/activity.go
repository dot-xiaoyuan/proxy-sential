package store

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

const defaultActivityEventLimit = 5000
const defaultActivityOverviewEventLimit = 100000

func activitySampleLimit(accessLimit int) int {
	if accessLimit <= 0 {
		accessLimit = 50
	}
	limit := accessLimit * 20
	if limit < 200 {
		return 200
	}
	if limit > defaultActivityEventLimit {
		return defaultActivityEventLimit
	}
	return limit
}

type activityBucket struct {
	count    int
	lastSeen string
}

type activityIPBucket struct {
	count    int
	lastSeen string
	domains  map[string]activityBucket
}

func BuildActivityProfile(ip string, events []normalized.Event, accessLimit int) ActivityProfile {
	if accessLimit <= 0 {
		accessLimit = 50
	}
	profile := ActivityProfile{
		IP:                 ip,
		Window:             "latest-run",
		EventTypeCounts:    []ActivityCount{},
		ProtocolCounts:     []ActivityCount{},
		TopDomains:         []ActivityCount{},
		TopHTTPHosts:       []ActivityCount{},
		TopTLSSNI:          []ActivityCount{},
		TopUserAgents:      []ActivityCount{},
		TopTLSFingerprints: []ActivityCount{},
		TopDstPorts:        []ActivityCount{},
		TopDstIPs:          []ActivityCount{},
		RecentAccesses:     []ActivityAccess{},
	}

	eventTypes := map[string]activityBucket{}
	protocols := map[string]activityBucket{}
	domains := map[string]activityBucket{}
	httpHosts := map[string]activityBucket{}
	tlsSNI := map[string]activityBucket{}
	userAgents := map[string]activityBucket{}
	tlsFingerprints := map[string]activityBucket{}
	dstPorts := map[string]activityBucket{}
	dstIPs := map[string]activityBucket{}

	for _, event := range events {
		if subjectIP(event) != ip {
			continue
		}
		profile.EventCount++
		trackBounds(&profile, event.Timestamp)
		increment(eventTypes, event.Type, event.Timestamp)
		increment(protocols, stringFromMap(event.Flow, "proto"), event.Timestamp)
		increment(dstIPs, stringFromMap(event.Flow, "dst_ip"), event.Timestamp)
		if port := intFromMap(event.Flow, "dst_port"); port > 0 {
			increment(dstPorts, fmt.Sprintf("%d", port), event.Timestamp)
		}

		switch event.Type {
		case "dns":
			increment(domains, stringFromMap(event.Payload, "query"), event.Timestamp)
		case "http":
			host := stringFromMap(event.Payload, "host")
			increment(domains, host, event.Timestamp)
			increment(httpHosts, host, event.Timestamp)
			increment(userAgents, stringFromMap(event.Payload, "user_agent"), event.Timestamp)
		case "tls":
			sni := stringFromMap(event.Payload, "sni")
			increment(domains, sni, event.Timestamp)
			increment(tlsSNI, sni, event.Timestamp)
			increment(tlsFingerprints, "ja3:"+stringFromMap(event.Payload, "ja3"), event.Timestamp)
			increment(tlsFingerprints, "ja4:"+stringFromMap(event.Payload, "ja4"), event.Timestamp)
		}

		if access := accessForEvent(event); access.Target != "" {
			profile.RecentAccesses = append(profile.RecentAccesses, access)
		}
	}

	sort.Slice(profile.RecentAccesses, func(i, j int) bool {
		return profile.RecentAccesses[i].Timestamp > profile.RecentAccesses[j].Timestamp
	})
	if len(profile.RecentAccesses) > accessLimit {
		profile.RecentAccesses = profile.RecentAccesses[:accessLimit]
	}

	profile.EventTypeCounts = topActivityCounts(eventTypes, 20)
	profile.ProtocolCounts = topActivityCounts(protocols, 20)
	profile.TopDomains = topActivityCounts(domains, 30)
	profile.TopHTTPHosts = topActivityCounts(httpHosts, 20)
	profile.TopTLSSNI = topActivityCounts(tlsSNI, 20)
	profile.TopUserAgents = topActivityCounts(userAgents, 20)
	profile.TopTLSFingerprints = topActivityCounts(tlsFingerprints, 20)
	profile.TopDstPorts = topActivityCounts(dstPorts, 20)
	profile.TopDstIPs = topActivityCounts(dstIPs, 30)
	return profile
}

func BuildActivityOverview(sensorID string, window string, events []normalized.Event, risks map[string]risk.Snapshot) ActivityOverview {
	if window == "" {
		window = "1h"
	}
	overview := ActivityOverview{
		SensorID:           sensorID,
		Window:             window,
		EventTypeCounts:    []ActivityCount{},
		ProtocolCounts:     []ActivityCount{},
		TopDomains:         []ActivityCount{},
		TopHTTPHosts:       []ActivityCount{},
		TopTLSSNI:          []ActivityCount{},
		TopUserAgents:      []ActivityCount{},
		TopTLSFingerprints: []ActivityCount{},
		TopDstPorts:        []ActivityCount{},
		TopDstIPs:          []ActivityCount{},
		TopSourceIPs:       []ActivityCount{},
		TopActiveRiskIPs:   []ActivityIPSummary{},
	}

	eventTypes := map[string]activityBucket{}
	protocols := map[string]activityBucket{}
	domains := map[string]activityBucket{}
	httpHosts := map[string]activityBucket{}
	tlsSNI := map[string]activityBucket{}
	userAgents := map[string]activityBucket{}
	tlsFingerprints := map[string]activityBucket{}
	dstPorts := map[string]activityBucket{}
	dstIPs := map[string]activityBucket{}
	sourceIPs := map[string]activityBucket{}
	perIP := map[string]*activityIPBucket{}

	for _, event := range events {
		eventSensorID := stringFromMap(event.Observer, "sensor_id")
		if sensorID != "" && eventSensorID != "" && eventSensorID != sensorID {
			continue
		}
		overview.EventCount++
		trackOverviewBounds(&overview, event.Timestamp)
		increment(eventTypes, event.Type, event.Timestamp)
		increment(protocols, stringFromMap(event.Flow, "proto"), event.Timestamp)
		increment(dstIPs, stringFromMap(event.Flow, "dst_ip"), event.Timestamp)
		if port := intFromMap(event.Flow, "dst_port"); port > 0 {
			increment(dstPorts, fmt.Sprintf("%d", port), event.Timestamp)
		}

		srcIP := subjectIP(event)
		if srcIP != "" {
			increment(sourceIPs, srcIP, event.Timestamp)
			bucket := perIP[srcIP]
			if bucket == nil {
				bucket = &activityIPBucket{domains: map[string]activityBucket{}}
				perIP[srcIP] = bucket
			}
			bucket.count++
			if event.Timestamp > bucket.lastSeen {
				bucket.lastSeen = event.Timestamp
			}
		}

		switch event.Type {
		case "dns":
			domain := stringFromMap(event.Payload, "query")
			increment(domains, domain, event.Timestamp)
			if srcIP != "" {
				increment(perIP[srcIP].domains, domain, event.Timestamp)
			}
		case "http":
			host := stringFromMap(event.Payload, "host")
			increment(domains, host, event.Timestamp)
			increment(httpHosts, host, event.Timestamp)
			increment(userAgents, stringFromMap(event.Payload, "user_agent"), event.Timestamp)
			if srcIP != "" {
				increment(perIP[srcIP].domains, host, event.Timestamp)
			}
		case "tls":
			sni := stringFromMap(event.Payload, "sni")
			increment(domains, sni, event.Timestamp)
			increment(tlsSNI, sni, event.Timestamp)
			increment(tlsFingerprints, "ja3:"+stringFromMap(event.Payload, "ja3"), event.Timestamp)
			increment(tlsFingerprints, "ja4:"+stringFromMap(event.Payload, "ja4"), event.Timestamp)
			if srcIP != "" {
				increment(perIP[srcIP].domains, sni, event.Timestamp)
			}
		}
	}

	overview.ActiveIPCount = len(perIP)
	overview.AccessObjectCount = len(domains)
	overview.EventTypeCounts = topActivityCounts(eventTypes, 20)
	overview.ProtocolCounts = topActivityCounts(protocols, 20)
	overview.TopDomains = topActivityCounts(domains, 20)
	overview.TopHTTPHosts = topActivityCounts(httpHosts, 20)
	overview.TopTLSSNI = topActivityCounts(tlsSNI, 20)
	overview.TopUserAgents = topActivityCounts(userAgents, 20)
	overview.TopTLSFingerprints = topActivityCounts(tlsFingerprints, 20)
	overview.TopDstPorts = topActivityCounts(dstPorts, 20)
	overview.TopDstIPs = topActivityCounts(dstIPs, 20)
	overview.TopSourceIPs = topActivityCounts(sourceIPs, 20)
	overview.TopActiveRiskIPs, overview.ActiveRiskIPCount = topActivityIPSummaries(perIP, risks, 50)
	return overview
}

func NormalizeActivityWindow(raw string) (string, time.Duration, error) {
	switch strings.TrimSpace(raw) {
	case "", "1h":
		return "1h", time.Hour, nil
	case "10m":
		return "10m", 10 * time.Minute, nil
	case "24h":
		return "24h", 24 * time.Hour, nil
	case "7d":
		return "7d", 7 * 24 * time.Hour, nil
	default:
		return "", 0, fmt.Errorf("window must be one of 10m, 1h, 24h, 7d")
	}
}

func trackBounds(profile *ActivityProfile, timestamp string) {
	if timestamp == "" {
		return
	}
	if profile.FirstSeen == "" || timestamp < profile.FirstSeen {
		profile.FirstSeen = timestamp
	}
	if profile.LastSeen == "" || timestamp > profile.LastSeen {
		profile.LastSeen = timestamp
	}
}

func trackOverviewBounds(overview *ActivityOverview, timestamp string) {
	if timestamp == "" {
		return
	}
	if overview.FirstSeen == "" || timestamp < overview.FirstSeen {
		overview.FirstSeen = timestamp
	}
	if overview.LastSeen == "" || timestamp > overview.LastSeen {
		overview.LastSeen = timestamp
	}
}

func increment(buckets map[string]activityBucket, value string, timestamp string) {
	incrementBy(buckets, value, timestamp, 1)
}

func incrementBy(buckets map[string]activityBucket, value string, timestamp string, count int) {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasSuffix(value, ":") {
		return
	}
	if count <= 0 {
		count = 1
	}
	bucket := buckets[value]
	bucket.count += count
	if timestamp > bucket.lastSeen {
		bucket.lastSeen = timestamp
	}
	buckets[value] = bucket
}

func topActivityCounts(buckets map[string]activityBucket, limit int) []ActivityCount {
	items := make([]ActivityCount, 0, len(buckets))
	for value, bucket := range buckets {
		items = append(items, ActivityCount{Value: value, Count: bucket.count, LastSeen: bucket.lastSeen})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		if items[i].LastSeen != items[j].LastSeen {
			return items[i].LastSeen > items[j].LastSeen
		}
		return items[i].Value < items[j].Value
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	if items == nil {
		return []ActivityCount{}
	}
	return items
}

func topActivityIPSummaries(perIP map[string]*activityIPBucket, risks map[string]risk.Snapshot, limit int) ([]ActivityIPSummary, int) {
	items := make([]ActivityIPSummary, 0)
	for ip, bucket := range perIP {
		snapshot, ok := risks[ip]
		if !ok || snapshot.Level == "" || snapshot.Level == "normal" {
			continue
		}
		items = append(items, ActivityIPSummary{
			IP:         ip,
			EventCount: bucket.count,
			RiskLevel:  snapshot.Level,
			Score:      snapshot.Score,
			TopDomains: topActivityCounts(bucket.domains, 5),
			LastSeen:   bucket.lastSeen,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		leftRank, _ := levelRank(items[i].RiskLevel)
		rightRank, _ := levelRank(items[j].RiskLevel)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		if items[i].EventCount != items[j].EventCount {
			return items[i].EventCount > items[j].EventCount
		}
		return items[i].IP < items[j].IP
	})
	total := len(items)
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	if items == nil {
		return []ActivityIPSummary{}, total
	}
	return items, total
}

func riskSnapshotMap(snapshots []risk.Snapshot) map[string]risk.Snapshot {
	result := make(map[string]risk.Snapshot, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot.IP != "" {
			result[snapshot.IP] = snapshot
		}
	}
	return result
}

func accessForEvent(event normalized.Event) ActivityAccess {
	access := ActivityAccess{
		Timestamp: event.Timestamp,
		EventID:   event.EventID,
		Type:      event.Type,
		DstIP:     stringFromMap(event.Flow, "dst_ip"),
		DstPort:   intFromMap(event.Flow, "dst_port"),
		Proto:     stringFromMap(event.Flow, "proto"),
	}
	switch event.Type {
	case "dns":
		access.TargetKind = "dns_query"
		access.Target = stringFromMap(event.Payload, "query")
	case "http":
		access.TargetKind = "http_host"
		access.Target = joinHostURL(stringFromMap(event.Payload, "host"), stringFromMap(event.Payload, "url"))
		access.Method = stringFromMap(event.Payload, "method")
		access.UserAgent = stringFromMap(event.Payload, "user_agent")
	case "tls":
		access.TargetKind = "tls_sni"
		access.Target = stringFromMap(event.Payload, "sni")
	case "flow":
		access.TargetKind = "dst_ip"
		access.Target = access.DstIP
	default:
		access.TargetKind = event.Type
		access.Target = access.DstIP
	}
	return access
}

func joinHostURL(host string, path string) string {
	host = strings.TrimSpace(host)
	path = strings.TrimSpace(path)
	if host == "" {
		return path
	}
	if path == "" || path == "/" {
		return host
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return host + path
}

func subjectIP(event normalized.Event) string {
	if value := stringFromMap(event.Subject, "ip"); value != "" {
		return value
	}
	return stringFromMap(event.Flow, "src_ip")
}

func intFromMap(values map[string]any, key string) int {
	if values == nil {
		return 0
	}
	switch value := values[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case jsonNumber:
		parsed, _ := value.Int64()
		return int(parsed)
	default:
		return 0
	}
}

type jsonNumber interface {
	Int64() (int64, error)
}
