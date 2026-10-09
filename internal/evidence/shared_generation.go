package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
)

// SharedWindowsBySession partitions standard observations before aggregation.
// Identity boundaries cut windows; they never establish identity authority. The
// evaluator still checks registered sources, coverage and conflicts afterwards.
func SharedWindowsBySession(events []normalized.Event, sessions []policy.Session, from, to time.Time, complete bool) []sharedaccess.Window {
	type scopeKey struct{ IP, Sensor, Campus, Domain string }
	type seenRecord struct {
		Digest [32]byte
		Scope  scopeKey
	}
	seen := map[string]seenRecord{}
	conflicting := map[scopeKey]bool{}
	encodingFailed := false
	for _, event := range events {
		switch event.Type {
		case "http", "tls", "quic", "device", "dns", "flow", "connection":
		default:
			continue
		}
		if isInfrastructureRole(subjectString(event, "entity_role")) {
			continue
		}
		at, e := time.Parse(time.RFC3339Nano, event.Timestamp)
		ip, ipError := netip.ParseAddr(subjectString(event, "ip"))
		if e != nil || ipError != nil || ip.IsUnspecified() || ip.IsMulticast() || event.EventID == "" {
			complete = false
			continue
		}
		if at.Before(from) || at.After(to) {
			continue
		}
		scope := scopeKey{ip.Unmap().String(), stringValue(event.Observer, "sensor_id"), subjectString(event, "campus_id"), stringValue(event.Payload, "access_domain")}
		identity, _ := json.Marshal([]string{scope.Sensor, event.Source, stringValue(event.Observer, "collector_instance_id"), event.EventID})
		raw, encodeErr := json.Marshal(event)
		if encodeErr != nil {
			complete = false
			encodingFailed = true
			continue
		}
		digest := sha256.Sum256(raw)
		if previous, ok := seen[string(identity)]; ok && previous.Digest != digest {
			conflicting[scope] = true
			conflicting[previous.Scope] = true
		} else if !ok {
			seen[string(identity)] = seenRecord{digest, scope}
		}
	}
	type key struct{ IP, Campus, Domain string }
	boundaries := map[key][]time.Time{}
	for _, session := range sessions {
		ip, err := netip.ParseAddr(session.IP)
		if err != nil {
			continue
		}
		k := key{ip.Unmap().String(), session.CampusID, session.AccessDomain}
		for _, at := range []time.Time{session.StartedAt, session.EndedAt} {
			if at.After(from) && at.Before(to) {
				boundaries[k] = append(boundaries[k], at)
			}
		}
	}
	for k, values := range boundaries {
		sort.Slice(values, func(i, j int) bool { return values[i].Before(values[j]) })
		unique := []time.Time{from}
		for _, at := range values {
			if !at.Equal(unique[len(unique)-1]) {
				unique = append(unique, at)
			}
		}
		boundaries[k] = append(unique, to)
	}
	type partition struct {
		K     key
		Index int
	}
	grouped := map[partition][]normalized.Event{}
	unpartitioned := []normalized.Event{}
	for _, event := range events {
		ip := sharedString(event.Subject, "ip")
		if parsed, err := netip.ParseAddr(ip); err == nil {
			ip = parsed.Unmap().String()
		}
		campus := sharedString(event.Subject, "campus_id")
		if campus == "" {
			campus = sharedString(event.Payload, "campus_id")
		}
		domain := sharedString(event.Payload, "access_domain")
		if domain == "" {
			domain = sharedString(event.Subject, "access_domain")
		}
		k := key{ip, campus, domain}
		points, ok := boundaries[k]
		at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if !ok || err != nil {
			unpartitioned = append(unpartitioned, event)
			continue
		}
		if at.Before(from) || at.After(to) {
			continue
		}
		index := sort.Search(len(points), func(i int) bool { return points[i].After(at) }) - 1
		if index == len(points)-1 {
			index--
		}
		grouped[partition{k, index}] = append(grouped[partition{k, index}], event)
	}
	out := SharedWindows(unpartitioned, from, to, complete)
	for part, observations := range grouped {
		points := boundaries[part.K]
		end := points[part.Index+1]
		// A session ending at the boundary is not active there. Keep the preceding
		// window strictly before it while assigning equal-time events to the new one.
		if end.Before(to) {
			end = end.Add(-time.Nanosecond)
		}
		out = append(out, SharedWindows(observations, points[part.Index], end, complete)...)
	}
	for i := range out {
		window := &out[i]
		changed := false
		if encodingFailed {
			addSharedEncodingConflict(window)
			changed = true
		}
		if conflicting[scopeKey{window.IP, window.SensorID, window.CampusID, window.AccessDomain}] {
			found := false
			for _, reason := range window.Conflicts {
				if reason == "duplicate_event_changed" {
					found = true
				}
			}
			if !found {
				window.Conflicts = append(window.Conflicts, "duplicate_event_changed")
			}
			changed = true
		}
		if changed {
			sort.Strings(window.Conflicts)
			window.ID = ""
			raw, _ := json.Marshal(window)
			sum := sha256.Sum256(raw)
			window.ID = "shared-" + hex.EncodeToString(sum[:16])
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].From.Equal(out[j].From) {
			return out[i].From.Before(out[j].From)
		}
		return out[i].ID < out[j].ID
	})
	return out
}
func sharedString(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}
