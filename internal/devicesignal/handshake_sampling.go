package devicesignal

import (
	"cmp"
	"net"
	"slices"
)

// RouterSamplingSnapshot applies to one capture bucket. The lookup publishes
// an immutable set (at most 2048 exact IP/MAC pairs).
type RouterSamplingSnapshot struct {
	Keys               map[handshakeKey]struct{}
	LookupFailed       bool
	ReusedPreviousList bool
}

type missingRouterActivity struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Reason string `json:"reason"`
}

// Reasons describe what this filtered socket actually delivered. Kernel
// drops and frames too short to recover an IP/MAC stay in bucket coverage.
type routerSamplingCoverage struct {
	Keys               int                     `json:"keys"`
	RetainedActivity   int                     `json:"retained_activity"`
	LookupFailed       bool                    `json:"lookup_failed"`
	ReusedPreviousList bool                    `json:"reused_previous_list"`
	Reasons            map[string]int          `json:"missing_counts"`
	Missing            []missingRouterActivity `json:"missing,omitempty"`
}

const (
	routerNoMatchingFrame  = "no_matching_frame"
	routerParseIncomplete  = "parse_incomplete"
	routerNoUsableActivity = "no_usable_activity"
	routerMixedVLAN        = "mixed_vlan"
	routerKeyLimit         = "key_limit"
	routerOutputLimit      = "output_limit"
)

func (b *captureBucket) noteUnretainedRouter(key handshakeKey, reason string) {
	if _, ok := b.authenticatedRouters[key]; !ok {
		return
	}
	if b.routerFrameReasons == nil {
		b.routerFrameReasons = make(map[handshakeKey]string)
	}
	// A candidate lost to the key limit takes precedence over a parse
	// failure, which in turn is more informative than excluded traffic.
	prev := b.routerFrameReasons[key]
	if prev == "" || reason == routerKeyLimit || (reason == routerParseIncomplete && prev == routerNoUsableActivity) {
		b.routerFrameReasons[key] = reason
	}
}

func (b *captureBucket) routerSamplingCoverage(kept []handshakeKey, snapshot RouterSamplingSnapshot) routerSamplingCoverage {
	selected := make(map[handshakeKey]bool, len(kept))
	for _, k := range kept {
		selected[k] = true
	}
	stats := routerSamplingCoverage{Keys: len(b.authenticatedRouters), LookupFailed: snapshot.LookupFailed, ReusedPreviousList: snapshot.ReusedPreviousList, Reasons: make(map[string]int)}
	for k := range b.authenticatedRouters {
		s := b.handshakes[k]
		reason := b.routerFrameReasons[k]
		switch {
		case s != nil && s.activity != nil:
			if selected[k] {
				stats.RetainedActivity++
				continue
			}
			reason = routerOutputLimit
		case s != nil && s.activityMixedVLAN:
			reason = routerMixedVLAN
		case s != nil && s.truncated > 0:
			reason = routerParseIncomplete
		case reason != "":
		case s != nil:
			reason = routerNoUsableActivity
		default:
			reason = routerNoMatchingFrame
		}
		stats.Reasons[reason]++
		stats.Missing = append(stats.Missing, missingRouterActivity{IP: k.IP.String(), MAC: net.HardwareAddr(k.MAC[:]).String(), Reason: reason})
	}
	slices.SortFunc(stats.Missing, func(a, b missingRouterActivity) int {
		if d := cmp.Compare(a.IP, b.IP); d != 0 {
			return d
		}
		return cmp.Compare(a.MAC, b.MAC)
	})
	return stats
}
