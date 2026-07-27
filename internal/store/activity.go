package store

import (
	"fmt"
	"sort"
	"strings"

	"proxy-sentinel/internal/normalized"
)

const defaultActivityEventLimit = 5000

type activityBucket struct {
	count    int
	lastSeen string
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

func increment(buckets map[string]activityBucket, value string, timestamp string) {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasSuffix(value, ":") {
		return
	}
	bucket := buckets[value]
	bucket.count++
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
