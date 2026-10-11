// Package poison reproduces the legacy "poison behaviour" check as a pure
// evaluation over observed destinations: a subject reaching configured
// sensitive ranges, or reaching many internal destinations in a window.
//
// The evaluator performs no I/O so the rules can be replayed and previewed
// before they are ever enabled on live traffic.
package poison

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	BehaviorConfiguredRange = "configured_ip_range"
	BehaviorHighFrequency   = "high_frequency_internal"

	DirectionAny  = "any"
	DirectionUp   = "up"
	DirectionDown = "down"
)

type Rule struct {
	RuleID        string   `json:"rule_id"`
	Name          string   `json:"name"`
	Enabled       bool     `json:"enabled"`
	BehaviorType  string   `json:"behavior_type"`
	TargetType    string   `json:"target_type"`
	Targets       []string `json:"targets"`
	WindowSeconds int      `json:"window_seconds"`
	Threshold     int      `json:"threshold"`
	Direction     string   `json:"direction"`
}

// Observation is one directed contact from a subject to a destination.
type Observation struct {
	SubjectIP string
	DstIP     string
	Proto     string
	Direction string
	At        time.Time
	// Count is the number of raw contacts this aggregate represents. Callers
	// that aggregate in storage set it; a zero value means one contact.
	Count int
}

type Finding struct {
	RuleID             string
	BehaviorType       string
	SubjectIP          string
	MatchedTargets     []string
	UniqueDestinations int
	HitCount           int
	Direction          string
	WindowStart        time.Time
	WindowEnd          time.Time
	FirstSeen          time.Time
	LastSeen           time.Time
}

type compiledRule struct {
	rule   Rule
	prefix []netip.Prefix
	addrs  map[netip.Addr]struct{}
	names  []string
}

func NormalizeRule(rule Rule) Rule {
	rule.BehaviorType = strings.ToLower(strings.TrimSpace(rule.BehaviorType))
	if rule.BehaviorType == "" {
		rule.BehaviorType = BehaviorConfiguredRange
	}
	rule.TargetType = strings.ToLower(strings.TrimSpace(rule.TargetType))
	if rule.TargetType == "" {
		rule.TargetType = "cidr"
	}
	rule.Direction = strings.ToLower(strings.TrimSpace(rule.Direction))
	if rule.Direction == "" {
		rule.Direction = DirectionAny
	}
	if rule.WindowSeconds <= 0 {
		rule.WindowSeconds = 3600
	}
	if rule.Threshold <= 0 {
		rule.Threshold = 1
	}
	seen := map[string]bool{}
	targets := make([]string, 0, len(rule.Targets))
	for _, target := range rule.Targets {
		target = strings.TrimSpace(target)
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, target)
	}
	sort.Strings(targets)
	rule.Targets = targets
	return rule
}

func ValidateRule(rule *Rule) error {
	if rule == nil {
		return fmt.Errorf("规则不能为空")
	}
	normalized := NormalizeRule(*rule)
	*rule = normalized
	rule.RuleID = strings.TrimSpace(rule.RuleID)
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.RuleID == "" || rule.Name == "" {
		return fmt.Errorf("规则标识与名称不能为空")
	}
	if len(rule.RuleID) > 128 || len(rule.Name) > 128 {
		return fmt.Errorf("规则标识或名称过长")
	}
	if rule.BehaviorType != BehaviorConfiguredRange && rule.BehaviorType != BehaviorHighFrequency {
		return fmt.Errorf("行为类型不受支持")
	}
	if rule.Direction != DirectionAny && rule.Direction != DirectionUp && rule.Direction != DirectionDown {
		return fmt.Errorf("方向必须是 any、up 或 down")
	}
	if rule.WindowSeconds < 60 || rule.WindowSeconds > 86400 {
		return fmt.Errorf("窗口必须在 60 到 86400 秒之间")
	}
	if rule.Threshold < 1 {
		return fmt.Errorf("阈值必须大于 0")
	}
	if rule.BehaviorType == BehaviorConfiguredRange {
		if len(rule.Targets) == 0 {
			return fmt.Errorf("按配置网段判定时必须至少填写一个目标")
		}
		if _, err := compileRule(*rule); err != nil {
			return err
		}
	}
	return nil
}

func compileRule(rule Rule) (compiledRule, error) {
	compiled := compiledRule{rule: rule, addrs: map[netip.Addr]struct{}{}}
	for _, target := range rule.Targets {
		switch rule.TargetType {
		case "domain":
			compiled.names = append(compiled.names, strings.ToLower(target))
			continue
		case "ip":
			addr, err := netip.ParseAddr(target)
			if err != nil {
				return compiled, fmt.Errorf("目标 %q 不是合法 IP", target)
			}
			compiled.addrs[addr.Unmap()] = struct{}{}
			continue
		default:
			if prefix, err := netip.ParsePrefix(target); err == nil {
				compiled.prefix = append(compiled.prefix, prefix.Masked())
				continue
			}
			addr, err := netip.ParseAddr(target)
			if err != nil {
				return compiled, fmt.Errorf("目标 %q 既不是 CIDR 也不是 IP", target)
			}
			compiled.addrs[addr.Unmap()] = struct{}{}
		}
	}
	return compiled, nil
}

// Evaluate returns one finding per subject that meets the rule threshold.
func Evaluate(rule Rule, observations []Observation) []Finding {
	normalized := NormalizeRule(rule)
	if !normalized.Enabled {
		return nil
	}
	compiled, err := compileRule(normalized)
	if err != nil {
		return nil
	}
	type subjectState struct {
		targets    map[string]struct{}
		dest       map[string]struct{}
		hits       int
		first      time.Time
		last       time.Time
		directions map[string]int
	}
	states := map[string]*subjectState{}
	for _, observation := range observations {
		subject := strings.TrimSpace(observation.SubjectIP)
		dest := strings.TrimSpace(observation.DstIP)
		if subject == "" || dest == "" || !directionAllowed(normalized.Direction, observation.Direction) {
			continue
		}
		subjectAddr, err := netip.ParseAddr(subject)
		if err != nil {
			continue
		}
		destAddr, err := netip.ParseAddr(dest)
		if err != nil || excludedDestination(subjectAddr.Unmap(), destAddr.Unmap()) {
			continue
		}
		matched, target := false, ""
		if normalized.BehaviorType == BehaviorHighFrequency {
			// Internal destinations are the signal; configured targets, when
			// present, only narrow it further.
			if !IsInternal(destAddr.Unmap()) {
				continue
			}
			matched = true
			if len(compiled.prefix)+len(compiled.addrs) > 0 {
				matched, target = matchedTarget(compiled, destAddr.Unmap())
			}
		} else {
			matched, target = matchedTarget(compiled, destAddr.Unmap())
		}
		if !matched {
			continue
		}
		state := states[subject]
		if state == nil {
			state = &subjectState{targets: map[string]struct{}{}, dest: map[string]struct{}{}, directions: map[string]int{}}
			states[subject] = state
		}
		contacts := observation.Count
		if contacts <= 0 {
			contacts = 1
		}
		state.hits += contacts
		state.dest[dest] = struct{}{}
		if normalized.BehaviorType == BehaviorConfiguredRange && target != "" {
			state.targets[target] = struct{}{}
		}
		if state.first.IsZero() || observation.At.Before(state.first) {
			state.first = observation.At
		}
		if observation.At.After(state.last) {
			state.last = observation.At
		}
		if observation.Direction != "" {
			state.directions[observation.Direction]++
		}
	}
	findings := make([]Finding, 0, len(states))
	for subject, state := range states {
		if state.hits < normalized.Threshold {
			continue
		}
		targets := make([]string, 0, len(state.targets))
		for target := range state.targets {
			targets = append(targets, target)
		}
		sort.Strings(targets)
		findings = append(findings, Finding{
			RuleID:             normalized.RuleID,
			BehaviorType:       normalized.BehaviorType,
			SubjectIP:          subject,
			MatchedTargets:     targets,
			UniqueDestinations: len(state.dest),
			HitCount:           state.hits,
			Direction:          dominantDirection(state.directions),
			WindowStart:        state.last.Add(-time.Duration(normalized.WindowSeconds) * time.Second),
			WindowEnd:          state.last,
			FirstSeen:          state.first,
			LastSeen:           state.last,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].SubjectIP != findings[j].SubjectIP {
			return findings[i].SubjectIP < findings[j].SubjectIP
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	return findings
}

func directionAllowed(ruleDirection, observed string) bool {
	if ruleDirection == "" || ruleDirection == DirectionAny {
		return true
	}
	observed = strings.ToLower(strings.TrimSpace(observed))
	switch ruleDirection {
	case DirectionUp:
		return observed == DirectionUp || observed == "outbound"
	case DirectionDown:
		return observed == DirectionDown || observed == "inbound"
	}
	return true
}

func dominantDirection(counts map[string]int) string {
	best, bestCount := "", 0
	for direction, count := range counts {
		if count > bestCount || (count == bestCount && direction < best) {
			best, bestCount = direction, count
		}
	}
	return best
}

// excludedDestination drops addresses that are never meaningful evidence: the
// subject itself, multicast, broadcast, loopback, link-local and unspecified.
func excludedDestination(subject, dest netip.Addr) bool {
	if !dest.IsValid() || !subject.IsValid() {
		return true
	}
	if dest == subject {
		return true
	}
	if dest.IsMulticast() || dest.IsLoopback() || dest.IsLinkLocalUnicast() || dest.IsLinkLocalMulticast() || dest.IsUnspecified() {
		return true
	}
	if dest.Is4() && dest == netip.MustParseAddr("255.255.255.255") {
		return true
	}
	return false
}

func matchedTarget(compiled compiledRule, dest netip.Addr) (bool, string) {
	if _, ok := compiled.addrs[dest]; ok {
		return true, dest.String()
	}
	for _, prefix := range compiled.prefix {
		if prefix.Contains(dest) {
			return true, prefix.String()
		}
	}
	if len(compiled.names) == 0 {
		return false, ""
	}
	// Domain targets cannot be matched against an IP observation; they are
	// resolved by the caller before evaluation.
	return false, ""
}

// IsInternal reports whether an address is inside the campus/private space the
// high-frequency behaviour targets.
func IsInternal(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	for _, prefix := range internalPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

var internalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// FindingID is stable for a rule, subject and observation window so replays do
// not create duplicate findings.
func FindingID(ruleID, subjectIP string, windowEnd time.Time) string {
	return fmt.Sprintf("dtt-%s-%s-%d", ruleID, subjectIP, windowEnd.UTC().Unix()/60)
}
