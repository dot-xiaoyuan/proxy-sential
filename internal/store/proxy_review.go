package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

const (
	defaultProxyReviewWindow = "7d"
	defaultProxyReviewLimit  = 100000
)

type proxyIdentity struct {
	accountID  string
	endpointID string
	accessID   string
}

type proxyReviewBucket struct {
	item               ProxyReviewCase
	accessIDs          map[string]struct{}
	destinations       map[string]activityBucket
	destinationIPs     map[string]activityBucket
	destinationDomains map[string]activityBucket
	tlsFingerprints    map[string]activityBucket
	protocols          map[string]activityBucket
	first              time.Time
	last               time.Time
	hasDomainHint      bool
}

// BuildProxyReviewResponse aggregates normalized TLS, QUIC and explicit proxy
// alert events by account/endpoint/IP. It is intentionally downstream of the
// normalized event boundary and never consumes collector-specific raw fields.
func BuildProxyReviewResponse(sensorID, window string, events []normalized.Event, risks map[string]risk.Snapshot) ProxyReviewResponse {
	if window == "" {
		window = defaultProxyReviewWindow
	}
	identities := latestProxyIdentities(events)
	buckets := map[string]*proxyReviewBucket{}
	acceptedEvents := 0
	for _, event := range events {
		if !isProxyReviewEvent(event) {
			continue
		}
		ip := subjectIP(event)
		if ip == "" {
			continue
		}
		identity := identities[ip]
		if value := stringFromMap(event.Subject, "account_id"); value != "" {
			identity.accountID = value
		}
		if value := stringFromMap(event.Subject, "endpoint_id"); value != "" {
			identity.endpointID = value
		}
		if value := stringFromMap(event.Subject, "access_id"); value != "" {
			identity.accessID = value
		}
		key := strings.Join([]string{identity.accountID, identity.endpointID, ip}, "|")
		bucket := buckets[key]
		if bucket == nil {
			bucket = &proxyReviewBucket{
				item: ProxyReviewCase{
					CaseID:             proxyReviewCaseID(key),
					IP:                 ip,
					AccountID:          identity.accountID,
					EndpointID:         identity.endpointID,
					AccessIDs:          []string{},
					Destinations:       []ActivityCount{},
					DestinationIPs:     []ActivityCount{},
					DestinationDomains: []ActivityCount{},
					TLSFingerprints:    []ActivityCount{},
					Protocols:          []ActivityCount{},
					RuleMatches:        []ProxyRuleMatch{},
					EvidenceIDs:        []string{},
					RiskLevel:          "normal",
					ReviewStatus:       ReviewStatusUnreviewed,
				},
				accessIDs:          map[string]struct{}{},
				destinations:       map[string]activityBucket{},
				destinationIPs:     map[string]activityBucket{},
				destinationDomains: map[string]activityBucket{},
				tlsFingerprints:    map[string]activityBucket{},
				protocols:          map[string]activityBucket{},
			}
			buckets[key] = bucket
		}
		weight := proxyReviewEventWeight(event)
		acceptedEvents += weight
		bucket.item.EventCount += weight
		addProxyReviewAccess(bucket, identity.accessID, event)
		addProxyReviewDestination(bucket, event)
		addProxyReviewFingerprints(bucket, event)
		addProxyReviewProtocol(bucket, event)
		trackProxyReviewBounds(bucket, event)
		switch event.Type {
		case "tls":
			bucket.item.TLSCount += weight
		case "quic":
			bucket.item.QUICCount += weight
		case "alert":
			bucket.item.AlertCount += weight
			bucket.item.RuleMatches = append(bucket.item.RuleMatches, proxyRuleMatch(event))
		}
		if eventHasVPNDomainHint(event) {
			bucket.hasDomainHint = true
		}
	}

	response := ProxyReviewResponse{SensorID: sensorID, Window: window, EventCount: acceptedEvents, Items: []ProxyReviewCase{}}
	accounts := map[string]struct{}{}
	endpoints := map[string]struct{}{}
	destinations := map[string]struct{}{}
	for _, bucket := range buckets {
		finalizeProxyReviewBucket(bucket, risks)
		response.Items = append(response.Items, bucket.item)
		addSetString(accounts, bucket.item.AccountID)
		addSetString(endpoints, bucket.item.EndpointID)
		for _, destination := range append(append([]ActivityCount{}, bucket.item.DestinationDomains...), bucket.item.DestinationIPs...) {
			addSetString(destinations, destination.Value)
		}
		if bucket.item.ConfidenceLevel == "high" {
			response.HighConfidenceCount++
		}
	}
	sort.Slice(response.Items, func(i, j int) bool {
		left, right := response.Items[i], response.Items[j]
		if proxyConfidenceRank(left.ConfidenceLevel) != proxyConfidenceRank(right.ConfidenceLevel) {
			return proxyConfidenceRank(left.ConfidenceLevel) > proxyConfidenceRank(right.ConfidenceLevel)
		}
		if left.RiskScore != right.RiskScore {
			return left.RiskScore > right.RiskScore
		}
		if left.LastSeen != right.LastSeen {
			return left.LastSeen > right.LastSeen
		}
		return left.CaseID < right.CaseID
	})
	response.CaseCount = len(response.Items)
	response.AccountCount = len(accounts)
	response.EndpointCount = len(endpoints)
	response.DestinationCount = len(destinations)
	return response
}

func proxyReviewEventWeight(event normalized.Event) int {
	weight := intFromMap(event.Payload, "_aggregate_count")
	if weight <= 0 {
		return 1
	}
	return weight
}

func latestProxyIdentities(events []normalized.Event) map[string]proxyIdentity {
	type timedIdentity struct {
		identity proxyIdentity
		time     string
	}
	latest := map[string]timedIdentity{}
	for _, event := range events {
		if event.Type != "identity" || isInfrastructureEntityRole(stringFromMap(event.Subject, "entity_role")) {
			continue
		}
		ip := subjectIP(event)
		if ip == "" || event.Timestamp < latest[ip].time {
			continue
		}
		latest[ip] = timedIdentity{identity: proxyIdentity{
			accountID:  stringFromMap(event.Subject, "account_id"),
			endpointID: stringFromMap(event.Subject, "endpoint_id"),
			accessID:   stringFromMap(event.Subject, "access_id"),
		}, time: event.Timestamp}
	}
	result := map[string]proxyIdentity{}
	for ip, item := range latest {
		result[ip] = item.identity
	}
	return result
}

func isProxyReviewEvent(event normalized.Event) bool {
	switch event.Type {
	case "tls", "quic":
		return true
	case "alert":
		return evidence.IsVPNAlert(event.Payload)
	default:
		return false
	}
}

func eventHasVPNDomainHint(event normalized.Event) bool {
	for _, key := range []string{"sni", "server_name", "host", "query"} {
		if evidence.HasVPNHint(stringFromMap(event.Payload, key)) {
			return true
		}
	}
	return false
}

func addProxyReviewAccess(bucket *proxyReviewBucket, accessID string, event normalized.Event) {
	addSetString(bucket.accessIDs, accessID)
	if len(bucket.accessIDs) == 0 {
		addSetString(bucket.accessIDs, stringFromMap(event.Observer, "interface"))
	}
}

func addProxyReviewDestination(bucket *proxyReviewBucket, event normalized.Event) {
	weight := proxyReviewEventWeight(event)
	domain := stringFromMap(event.Payload, "sni")
	if domain == "" {
		domain = stringFromMap(event.Payload, "server_name")
	}
	dstIP := stringFromMap(event.Flow, "dst_ip")
	dstPort := intFromMap(event.Flow, "dst_port")
	if domain != "" {
		incrementBy(bucket.destinationDomains, domain, event.Timestamp, weight)
	}
	if dstIP != "" {
		value := dstIP
		if dstPort > 0 {
			value = fmt.Sprintf("%s:%d", dstIP, dstPort)
		}
		incrementBy(bucket.destinationIPs, value, event.Timestamp, weight)
	}
	target := domain
	if target == "" {
		target = dstIP
	}
	if target == "" {
		return
	}
	if dstPort > 0 {
		target = fmt.Sprintf("%s:%d", target, dstPort)
	}
	incrementBy(bucket.destinations, target, event.Timestamp, weight)
}

func addProxyReviewFingerprints(bucket *proxyReviewBucket, event normalized.Event) {
	if event.Type != "tls" && event.Type != "quic" {
		return
	}
	for _, key := range []string{"ja3", "ja4"} {
		if value := stringFromMap(event.Payload, key); value != "" {
			incrementBy(bucket.tlsFingerprints, key+":"+value, event.Timestamp, proxyReviewEventWeight(event))
		}
	}
}

func addProxyReviewProtocol(bucket *proxyReviewBucket, event normalized.Event) {
	protocol := strings.ToUpper(stringFromMap(event.Flow, "proto"))
	if event.Type == "quic" {
		protocol = "QUIC"
	} else if event.Type == "tls" {
		protocol = "TLS/" + firstNonEmpty(protocol, "TCP")
	} else if event.Type == "alert" {
		protocol = "ALERT/" + firstNonEmpty(protocol, "UNKNOWN")
	}
	incrementBy(bucket.protocols, protocol, event.Timestamp, proxyReviewEventWeight(event))
}

func trackProxyReviewBounds(bucket *proxyReviewBucket, event normalized.Event) {
	start := parsedProxyTime(stringFromMap(event.Flow, "start"))
	end := parsedProxyTime(stringFromMap(event.Flow, "end"))
	eventTime := parsedProxyTime(event.Timestamp)
	if start.IsZero() {
		start = eventTime
	}
	if end.IsZero() {
		end = eventTime
	}
	if bucket.first.IsZero() || (!start.IsZero() && start.Before(bucket.first)) {
		bucket.first = start
	}
	if bucket.last.IsZero() || end.After(bucket.last) {
		bucket.last = end
	}
}

func parsedProxyTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func proxyRuleMatch(event normalized.Event) ProxyRuleMatch {
	return ProxyRuleMatch{
		EventID:   event.EventID,
		Signature: firstNonEmpty(stringFromMap(event.Payload, "signature"), "代理/VPN/隧道规则命中"),
		Category:  stringFromMap(event.Payload, "category"),
		Action:    stringFromMap(event.Payload, "action"),
		Severity:  intFromMap(event.Payload, "severity"),
		Timestamp: event.Timestamp,
	}
}

func finalizeProxyReviewBucket(bucket *proxyReviewBucket, risks map[string]risk.Snapshot) {
	bucket.item.AccessIDs = sortedStringSet(bucket.accessIDs)
	bucket.item.Destinations = topActivityCounts(bucket.destinations, 20)
	bucket.item.DestinationIPs = topActivityCounts(bucket.destinationIPs, 20)
	bucket.item.DestinationDomains = topActivityCounts(bucket.destinationDomains, 20)
	bucket.item.TLSFingerprints = topActivityCounts(bucket.tlsFingerprints, 20)
	bucket.item.Protocols = topActivityCounts(bucket.protocols, 10)
	sort.Slice(bucket.item.RuleMatches, func(i, j int) bool {
		if bucket.item.RuleMatches[i].Timestamp != bucket.item.RuleMatches[j].Timestamp {
			return bucket.item.RuleMatches[i].Timestamp > bucket.item.RuleMatches[j].Timestamp
		}
		return bucket.item.RuleMatches[i].EventID < bucket.item.RuleMatches[j].EventID
	})
	if len(bucket.item.RuleMatches) > 0 {
		bucket.item.ConfidenceLevel = "high"
	} else if bucket.hasDomainHint {
		bucket.item.ConfidenceLevel = "medium"
	} else {
		bucket.item.ConfidenceLevel = "low"
	}
	if !bucket.first.IsZero() {
		bucket.item.FirstSeen = bucket.first.Format(time.RFC3339Nano)
	}
	if !bucket.last.IsZero() {
		bucket.item.LastSeen = bucket.last.Format(time.RFC3339Nano)
	}
	if !bucket.first.IsZero() && bucket.last.After(bucket.first) {
		bucket.item.DurationSeconds = int64(bucket.last.Sub(bucket.first).Seconds())
	}
	if snapshot, ok := proxyReviewRisk(bucket.item, risks); ok {
		bucket.item.RiskScore = snapshot.Score
		bucket.item.RiskLevel = snapshot.Level
		bucket.item.EvidenceIDs = append([]string{}, snapshot.EvidenceIDs...)
		bucket.item.ReviewStatus = firstNonEmpty(snapshot.ReviewStatus, ReviewStatusUnreviewed)
		bucket.item.ReviewReason = snapshot.ReviewReason
	}
}

func proxyReviewRisk(item ProxyReviewCase, risks map[string]risk.Snapshot) (risk.Snapshot, bool) {
	for _, key := range []string{"endpoint:" + item.EndpointID, "account:" + item.AccountID, "ip:" + item.IP, item.IP} {
		if snapshot, ok := risks[key]; ok && strings.TrimSpace(key) != "endpoint:" && strings.TrimSpace(key) != "account:" {
			return snapshot, true
		}
	}
	return risk.Snapshot{}, false
}

func ProxyReviewRiskMap(items []risk.Snapshot) map[string]risk.Snapshot {
	result := map[string]risk.Snapshot{}
	for _, item := range items {
		if item.SubjectType != "" && item.SubjectID != "" {
			result[item.SubjectType+":"+item.SubjectID] = item
		}
		if item.IP != "" {
			result["ip:"+item.IP] = item
			result[item.IP] = item
		}
	}
	return result
}

func proxyReviewCaseID(key string) string {
	sum := sha256.Sum256([]byte("proxy-review|" + key))
	return "proxy-" + hex.EncodeToString(sum[:])[:20]
}

func sortedStringSet(items map[string]struct{}) []string {
	result := make([]string, 0, len(items))
	for item := range items {
		if item != "" {
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}

func addSetString(items map[string]struct{}, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		items[value] = struct{}{}
	}
}

func proxyConfidenceRank(level string) int {
	switch level {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
