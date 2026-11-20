package discovery

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

const passiveBehaviorVersion = "passive-behavior/v1"

type PassiveBehaviorEvidence struct {
	Kind       string    `json:"kind"`
	Value      string    `json:"value"`
	BucketAt   time.Time `json:"bucket_at"`
	ObservedAt time.Time `json:"observed_at"`
	EventID    string    `json:"event_id"`
}

type PassiveBehavior struct {
	RuleVersion    string                    `json:"rule_version"`
	Status         string                    `json:"status"`
	Attribution    string                    `json:"attribution"`
	CandidateType  string                    `json:"candidate_type,omitempty"`
	OSHint         string                    `json:"os_hint,omitempty"`
	NTPTarget      string                    `json:"ntp_target,omitempty"`
	CadenceMinutes int                       `json:"cadence_minutes,omitempty"`
	AsOf           time.Time                 `json:"as_of"`
	Items          []PassiveBehaviorEvidence `json:"items"`
}

func PassiveBehaviorReadEnabled() bool {
	return os.Getenv("PROXY_SENTINEL_PASSIVE_BEHAVIOR_READ") == "true"
}

func PassiveBehaviorKey(sensor, site, domain, vlan, vrf, mac, ip string) string {
	if sensor == "" || site == "" || domain == "" {
		return ""
	}
	if mac != "" {
		return "device." + base64.RawURLEncoding.EncodeToString([]byte(HardwareIdentityKey(sensor, site, domain, vlan, vrf, mac)))
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	key, _ := json.Marshal([]string{sensor, site, domain, vlan, vrf, addr.Unmap().String()})
	return "ip." + base64.RawURLEncoding.EncodeToString(key)
}

type passiveBehaviorRule struct {
	domain, responsePort, candidate string
}

// An ecosystem domain is corroborative. A response from the device's own
// product port anchors the inference; an outbound attempt may be a viewer.
var passiveBehaviorRules = []passiveBehaviorRule{
	{"hikvision.com", "tcp/554", "video_device"},
	{"canon.com", "tcp/9100", "printer"},
}

func PassiveBehaviorDomain(query string) string {
	query = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(query)), ".")
	for _, rule := range passiveBehaviorRules {
		if query == rule.domain || strings.HasSuffix(query, "."+rule.domain) {
			return rule.domain
		}
	}
	return ""
}

// SummarizePassiveBehavior evaluates only current, independently attributed
// signals. The result is supplemental evidence and cannot confirm hardware.
func SummarizePassiveBehavior(items []PassiveBehaviorEvidence, trusted bool, at time.Time) PassiveBehavior {
	result := PassiveBehavior{RuleVersion: passiveBehaviorVersion, Status: "ready", Attribution: "ip", AsOf: at, Items: []PassiveBehaviorEvidence{}}
	if trusted {
		result.Attribution = "device"
	}
	kinds := make(map[string]map[string]struct{})
	recurrences := make(map[string]map[time.Time]struct{})
	for _, item := range items {
		if item.ObservedAt.After(at) || item.ObservedAt.Before(at.Add(-2*time.Hour)) {
			continue
		}
		result.Items = append(result.Items, item)
		if kinds[item.Kind] == nil {
			kinds[item.Kind] = make(map[string]struct{})
		}
		kinds[item.Kind][item.Value] = struct{}{}
		if item.Kind == "ntp" || item.Kind == "port_attempt" {
			key := item.Kind + "/" + item.Value
			if recurrences[key] == nil {
				recurrences[key] = make(map[time.Time]struct{})
			}
			recurrences[key][item.BucketAt] = struct{}{}
		}
	}
	if trusted {
		candidates := make(map[string]struct{})
		for _, rule := range passiveBehaviorRules {
			if _, domain := kinds["vendor_domain"][rule.domain]; !domain {
				continue
			}
			if _, response := kinds["port_response"][rule.responsePort]; response {
				candidates[rule.candidate] = struct{}{}
			}
		}
		if len(candidates) == 1 {
			for kind := range candidates {
				result.CandidateType = kind
			}
		}
		if len(kinds["tcp_os_clue"]) == 1 {
			for hint := range kinds["tcp_os_clue"] {
				result.OSHint = hint
			}
		}
	}
	ntpCount := 1
	for key, buckets := range recurrences {
		if target, ntp := strings.CutPrefix(key, "ntp/"); ntp && (len(buckets) > ntpCount || len(buckets) == ntpCount && result.NTPTarget != "" && target < result.NTPTarget) {
			result.NTPTarget, ntpCount = target, len(buckets)
		}
		minutes := stableBehaviorCadence(buckets)
		if minutes != 0 && (result.CadenceMinutes == 0 || minutes < result.CadenceMinutes) {
			result.CadenceMinutes = minutes
		}
	}
	return result
}

func stableBehaviorCadence(buckets map[time.Time]struct{}) int {
	if len(buckets) < 3 {
		return 0
	}
	times := make([]time.Time, 0, len(buckets))
	for bucket := range buckets {
		times = append(times, bucket)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	gap := times[1].Sub(times[0])
	for i := 2; i < len(times); i++ {
		if times[i].Sub(times[i-1]) != gap {
			return 0
		}
	}
	return int(gap / time.Minute)
}

type PassiveBehaviorOwner struct {
	Sensor, Site, Domain, VLAN, VRF, MAC, IP string
}

func ParsePassiveBehaviorKey(key string) (PassiveBehaviorOwner, bool) {
	prefix, encoded, found := strings.Cut(key, ".")
	if !found || len(key) > 1024 || (prefix != "device" && prefix != "ip") {
		return PassiveBehaviorOwner{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	var values []string
	if err != nil || json.Unmarshal(raw, &values) != nil {
		return PassiveBehaviorOwner{}, false
	}
	if prefix == "device" && len(values) == 8 && values[0] == "identity" && values[6] == "mac" && canonicalEndpointMAC("mac:"+values[7]) != "" {
		return PassiveBehaviorOwner{Sensor: values[1], Site: values[2], Domain: values[3], VLAN: values[4], VRF: values[5], MAC: values[7]}, true
	}
	if prefix == "ip" && len(values) == 6 {
		if _, err := netip.ParseAddr(values[5]); err == nil {
			return PassiveBehaviorOwner{Sensor: values[0], Site: values[1], Domain: values[2], VLAN: values[3], VRF: values[4], IP: values[5]}, true
		}
	}
	return PassiveBehaviorOwner{}, false
}
