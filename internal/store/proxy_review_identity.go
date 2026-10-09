package store

import (
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

type proxyIdentityScope struct{ sensor, campus, ip string }
type proxyIdentityPoint struct {
	at       time.Time
	identity proxyIdentity
	stop     bool
}
type proxyIdentityTimeline map[proxyIdentityScope][]proxyIdentityPoint

func proxyEventScope(event normalized.Event) proxyIdentityScope {
	return proxyIdentityScope{stringFromMap(event.Observer, "sensor_id"), firstNonEmpty(stringFromMap(event.Subject, "campus_id"), stringFromMap(event.Payload, "campus_id")), subjectIP(event)}
}

func proxyEventIdentity(event normalized.Event) proxyIdentity {
	return proxyIdentity{stringFromMap(event.Subject, "account_id"), stringFromMap(event.Subject, "endpoint_id"), stringFromMap(event.Subject, "access_id")}
}

func buildProxyIdentityTimeline(events []normalized.Event) proxyIdentityTimeline {
	result := proxyIdentityTimeline{}
	for _, event := range events {
		if event.Type != "identity" || isInfrastructureEntityRole(stringFromMap(event.Subject, "entity_role")) {
			continue
		}
		at, scope := parsedProxyTime(event.Timestamp), proxyEventScope(event)
		if at.IsZero() || scope.ip == "" {
			continue
		}
		status := strings.ToLower(firstNonEmpty(stringFromMap(event.Payload, "session_status"), stringFromMap(event.Payload, "action")))
		stop := status == "stop" || status == "logout" || status == "ended" || status == "accounting-stop"
		result[scope] = append(result[scope], proxyIdentityPoint{at, proxyEventIdentity(event), stop})
	}
	for scope, points := range result {
		sort.Slice(points, func(i, j int) bool { return points[i].at.Before(points[j].at) })
		merged := make([]proxyIdentityPoint, 0, len(points))
		for i := 0; i < len(points); {
			point := points[i]
			j := i + 1
			for j < len(points) && points[j].at.Equal(point.at) {
				if points[j].identity != points[i].identity || points[j].stop != points[i].stop {
					point.identity = proxyIdentity{}
				}
				j++
			}
			if point.stop {
				// A delayed logout for the old owner must not erase a newer
				// observed binding. An unspecified stop remains a boundary.
				if len(merged) > 0 && proxyIdentitiesConflict(point.identity, merged[len(merged)-1].identity) {
					i = j
					continue
				}
				point.identity = proxyIdentity{}
			}
			merged = append(merged, point)
			i = j
		}
		result[scope] = merged
	}
	return result
}

func proxyIdentitiesConflict(left, right proxyIdentity) bool {
	return left.accountID != "" && right.accountID != "" && left.accountID != right.accountID || left.endpointID != "" && right.endpointID != "" && left.endpointID != right.endpointID
}

func (timeline proxyIdentityTimeline) forEvent(event normalized.Event) proxyIdentity {
	explicit := proxyEventIdentity(event)
	at := parsedProxyTime(event.Timestamp)
	start, end := parsedProxyTime(stringFromMap(event.Flow, "start")), parsedProxyTime(stringFromMap(event.Flow, "end"))
	if start.IsZero() {
		start = at
	}
	if end.IsZero() {
		end = at
	}
	if at.IsZero() || start.IsZero() || end.Before(start) {
		return explicit
	}
	points := timeline[proxyEventScope(event)]
	i := sort.Search(len(points), func(i int) bool { return points[i].at.After(start) }) - 1
	if i < 0 {
		return explicit
	}
	identity := points[i].identity
	for j := i + 1; j < len(points) && !points[j].at.After(end); j++ {
		if points[j].identity != identity {
			return explicit
		}
	}
	if proxyIdentitiesConflict(explicit, identity) {
		return explicit
	}
	return proxyIdentity{firstNonEmpty(explicit.accountID, identity.accountID), firstNonEmpty(explicit.endpointID, identity.endpointID), firstNonEmpty(explicit.accessID, identity.accessID)}
}

func mergeProxyReviewIdentity(bucket *proxyReviewBucket, identity proxyIdentity) {
	if !bucket.identitySeen {
		bucket.item.AccountID, bucket.item.EndpointID = identity.accountID, identity.endpointID
		bucket.identitySeen = true
		return
	}
	if bucket.item.AccountID != identity.accountID {
		bucket.item.AccountID = ""
		bucket.identityMixed = true
	}
	if bucket.item.EndpointID != identity.endpointID {
		bucket.item.EndpointID = ""
		bucket.identityMixed = true
	}
}
