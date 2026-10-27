// Package netscan derives explainable internal scan clues from normalized flow events.
package netscan

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

type State string

const (
	Failed    State = "failed"
	Succeeded State = "succeeded"
	Unknown   State = "unknown"
)

type Mode string

const (
	Dense  Mode = "dense_internal_scan"
	Sparse Mode = "sparse_cross_subnet_scan"
)

type Zone struct{ ID, CampusID, CIDR string }
type Attempt struct {
	SensorID, CampusID, ConnectionID, EventID string
	SourceIP, DestinationIP                   string
	DestinationPort                           int
	State                                     State
	At                                        time.Time
}
type Config struct {
	Enabled                                                               bool
	ExcludedSourceCIDRs                                                   []string
	DenseWindow, SparseWindow                                             time.Duration
	DenseHosts, DenseAttempts, DenseConsecutive, SparseZones, SparsePorts int
	DenseFailureRatio, SparseFailureRatio, SparseThinRatio                float64
}
type Finding struct {
	Mode                                                     Mode
	SensorID, CampusID, SourceIP                             string
	WindowStart, WindowEnd                                   time.Time
	ZoneIDs                                                  []string
	ZoneTargetCounts                                         map[string]int
	UniqueDestinations, Attempts, Failed, Succeeded, Unknown int
	LongestConsecutive                                       int
	Ports                                                    []int
	EventIDs                                                 []string
	ThinZoneRatio                                            float64
	FailureRatio                                             float64
}

func defaults(c Config) Config {
	if c.DenseWindow <= 0 {
		c.DenseWindow = 5 * time.Minute
	}
	if c.SparseWindow <= 0 {
		c.SparseWindow = 10 * time.Minute
	}
	if c.DenseHosts <= 0 {
		c.DenseHosts = 32
	}
	if c.DenseAttempts <= 0 {
		c.DenseAttempts = 50
	}
	if c.DenseConsecutive <= 0 {
		c.DenseConsecutive = 16
	}
	if c.SparseZones <= 0 {
		c.SparseZones = 50
	}
	if c.SparsePorts <= 0 {
		c.SparsePorts = 3
	}
	if c.DenseFailureRatio <= 0 {
		c.DenseFailureRatio = .6
	}
	if c.SparseFailureRatio <= 0 {
		c.SparseFailureRatio = .5
	}
	if c.SparseThinRatio <= 0 {
		c.SparseThinRatio = .8
	}
	return c
}

type compiledZone struct {
	Zone
	prefix netip.Prefix
}
type matched struct {
	Attempt
	zone string
}

// Evaluate uses complete windows ending at now. The caller must reject truncated input.
func Evaluate(config Config, zones []Zone, attempts []Attempt, now time.Time) []Finding {
	if !config.Enabled {
		return nil
	}
	c := defaults(config)
	var compiled []compiledZone
	for _, z := range zones {
		p, err := netip.ParsePrefix(z.CIDR)
		if err == nil && z.ID != "" && z.CampusID != "" {
			compiled = append(compiled, compiledZone{z, p.Masked()})
		}
	}
	if len(compiled) == 0 {
		return nil
	}
	sort.Slice(compiled, func(i, j int) bool {
		if compiled[i].prefix.Bits() != compiled[j].prefix.Bits() {
			return compiled[i].prefix.Bits() > compiled[j].prefix.Bits()
		}
		return compiled[i].ID < compiled[j].ID
	})
	var excluded []netip.Prefix
	for _, raw := range c.ExcludedSourceCIDRs {
		if p, err := netip.ParsePrefix(raw); err == nil {
			excluded = append(excluded, p.Masked())
		}
	}
	seen := map[string]matched{}
	for _, a := range attempts {
		if a.SensorID == "" || a.CampusID == "" || a.SourceIP == "" || a.At.Before(now.Add(-c.SparseWindow)) || a.At.After(now) {
			continue
		}
		src, e1 := netip.ParseAddr(a.SourceIP)
		dst, e2 := netip.ParseAddr(a.DestinationIP)
		if e1 != nil || e2 != nil || src == dst || dst.IsMulticast() || dst.IsLoopback() || dst.IsLinkLocalUnicast() {
			continue
		}
		skip := false
		for _, p := range excluded {
			if p.Contains(src) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		zone := ""
		for _, z := range compiled {
			if z.CampusID == a.CampusID && z.prefix.Contains(dst) {
				zone = z.ID
				break
			}
		}
		if zone == "" {
			continue
		}
		id := a.ConnectionID
		if id == "" {
			id = a.EventID
		}
		if id == "" {
			continue
		}
		key := strings.Join([]string{a.SensorID, a.CampusID, a.SourceIP, id}, "\x00")
		if old, ok := seen[key]; !ok || (old.State == Unknown && a.State != Unknown) || (old.State == a.State && a.At.After(old.At)) || (old.State != Unknown && a.State != Unknown && a.At.After(old.At)) {
			seen[key] = matched{a, zone}
		}
	}
	groups := map[string][]matched{}
	for _, item := range seen {
		key := strings.Join([]string{item.SensorID, item.CampusID, item.SourceIP}, "\x00")
		groups[key] = append(groups[key], item)
	}
	var out []Finding
	for _, items := range groups {
		sort.Slice(items, func(i, j int) bool {
			if !items[i].At.Equal(items[j].At) {
				return items[i].At.Before(items[j].At)
			}
			return items[i].EventID < items[j].EventID
		})
		var dense []matched
		for _, item := range items {
			if !item.At.Before(now.Add(-c.DenseWindow)) {
				dense = append(dense, item)
			}
		}
		for _, f := range aggregate(Dense, dense, now, c.DenseWindow) {
			if f.UniqueDestinations >= c.DenseHosts && f.LongestConsecutive >= c.DenseConsecutive && f.Attempts >= c.DenseAttempts && coverageAndFailure(f, c.DenseFailureRatio) {
				out = append(out, f)
			}
		}
		for _, f := range aggregate(Sparse, items, now, c.SparseWindow) {
			if len(f.ZoneIDs) >= c.SparseZones && len(f.Ports) <= c.SparsePorts && f.ThinZoneRatio >= c.SparseThinRatio && coverageAndFailure(f, c.SparseFailureRatio) {
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceIP != out[j].SourceIP {
			return out[i].SourceIP < out[j].SourceIP
		}
		return out[i].Mode < out[j].Mode
	})
	return out
}

func coverageAndFailure(f Finding, minimum float64) bool {
	known := f.Failed + f.Succeeded
	return f.Attempts > 0 && float64(known)/float64(f.Attempts) >= .8 && known > 0 && f.FailureRatio >= minimum
}

func aggregate(mode Mode, items []matched, now time.Time, window time.Duration) []Finding {
	byZone := map[string][]matched{}
	if mode == Dense {
		for _, item := range items {
			byZone[item.zone] = append(byZone[item.zone], item)
		}
	} else {
		byZone["*"] = items
	}
	var result []Finding
	for _, group := range byZone {
		if len(group) == 0 {
			continue
		}
		f := Finding{Mode: mode, SensorID: group[0].SensorID, CampusID: group[0].CampusID, SourceIP: group[0].SourceIP, WindowStart: now.Add(-window), WindowEnd: now, ZoneTargetCounts: map[string]int{}}
		zones := map[string]map[string]bool{}
		dests := map[string]bool{}
		ports := map[int]bool{}
		ids := map[string]bool{}
		for _, item := range group {
			f.Attempts++
			dests[item.DestinationIP] = true
			ports[item.DestinationPort] = true
			if zones[item.zone] == nil {
				zones[item.zone] = map[string]bool{}
			}
			zones[item.zone][item.DestinationIP] = true
			switch item.State {
			case Failed:
				f.Failed++
			case Succeeded:
				f.Succeeded++
			default:
				f.Unknown++
			}
			if item.EventID != "" && len(ids) < 20 {
				ids[item.EventID] = true
			}
		}
		f.UniqueDestinations = len(dests)
		if mode == Dense {
			addresses := make([]netip.Addr, 0, len(dests))
			for raw := range dests {
				if addr, err := netip.ParseAddr(raw); err == nil {
					addresses = append(addresses, addr.Unmap())
				}
			}
			sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
			run := 0
			for i, addr := range addresses {
				if i > 0 && addresses[i-1].Next() == addr {
					run++
				} else {
					run = 1
				}
				if run > f.LongestConsecutive {
					f.LongestConsecutive = run
				}
			}
		}
		thin := 0
		for z, targets := range zones {
			f.ZoneIDs = append(f.ZoneIDs, z)
			f.ZoneTargetCounts[z] = len(targets)
			if len(targets) <= 2 {
				thin++
			}
		}
		sort.Strings(f.ZoneIDs)
		f.ThinZoneRatio = float64(thin) / float64(len(zones))
		known := f.Failed + f.Succeeded
		if known > 0 {
			f.FailureRatio = float64(f.Failed) / float64(known)
		}
		for p := range ports {
			f.Ports = append(f.Ports, p)
		}
		sort.Ints(f.Ports)
		for id := range ids {
			f.EventIDs = append(f.EventIDs, id)
		}
		sort.Strings(f.EventIDs)
		result = append(result, f)
	}
	return result
}
