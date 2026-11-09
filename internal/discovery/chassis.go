package discovery

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// ChassisCandidate links an infrastructure neighbor that advertises no usable
// management address to a discovered endpoint with the same vendor prefix. It
// is a candidate, never a silent merge: the operator decides whether the two
// MAC addresses belong to one chassis.
type ChassisCandidate struct {
	NeighborMAC  string   `json:"neighbor_mac"`
	NeighborName string   `json:"neighbor_name,omitempty"`
	PartnerMAC   string   `json:"partner_mac"`
	PartnerIP    string   `json:"partner_ip"`
	PartnerName  string   `json:"partner_name,omitempty"`
	Confidence   float64  `json:"confidence"`
	Evidence     []string `json:"evidence"`
}

type chassisObservation struct {
	origin      string
	mac         string
	ip          string
	deviceType  string
	name        string
	systemName  string
	server      string
	description string
}

var chassisNetworkTypes = map[string]bool{"router": true, "gateway": true, "switch": true, "access_point": true}

// ChassisCandidates derives same-chassis candidates from the current discovery
// index. A deterministic shared identifier is required for a merge; this method
// only surfaces the weak pairings that need operator confirmation.
func (r Repository) ChassisCandidates(ctx context.Context, window time.Duration) ([]ChassisCandidate, error) {
	if r.DB == nil {
		return nil, nil
	}
	if window <= 0 {
		window = 24 * time.Hour
	}
	rows, err := r.DB.QueryContext(ctx, `
SELECT origin,
       coalesce(data->>'mac',''),
       coalesce(data->>'ip',''),
       coalesce(data->>'device_type',''),
       coalesce(data->>'name',''),
       coalesce(data->'evidence'->'payload'->>'system_name',''),
       coalesce(data->'evidence'->'payload'->>'server',''),
       coalesce(data->'evidence'->'payload'->>'system_description','')
FROM discovery_observation_latest
WHERE valid_until > now()
  AND observed_at > now() - make_interval(secs => $1)
  AND coalesce(data->>'mac','') <> ''`, window.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byPrefix := map[string][]chassisObservation{}
	for rows.Next() {
		var o chassisObservation
		if err := rows.Scan(&o.origin, &o.mac, &o.ip, &o.deviceType, &o.name, &o.systemName, &o.server, &o.description); err != nil {
			return nil, err
		}
		o.mac = strings.ToLower(strings.TrimSpace(o.mac))
		if len(o.mac) < 17 {
			continue
		}
		prefix := o.mac[:14]
		byPrefix[prefix] = append(byPrefix[prefix], o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items := make([]ChassisCandidate, 0)
	for _, group := range byPrefix {
		neighbors := make([]chassisObservation, 0, len(group))
		partners := make([]chassisObservation, 0, len(group))
		for _, o := range group {
			switch {
			case (o.origin == "lldp" || o.origin == "cdp") && o.ip == "":
				neighbors = append(neighbors, o)
			case o.ip != "" && chassisNetworkTypes[o.deviceType]:
				partners = append(partners, o)
			}
		}
		for _, neighbor := range neighbors {
			if candidate, ok := bestChassisPartner(neighbor, partners); ok {
				items = append(items, candidate)
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Confidence == items[j].Confidence {
			return items[i].NeighborMAC < items[j].NeighborMAC
		}
		return items[i].Confidence > items[j].Confidence
	})
	return items, nil
}

func bestChassisPartner(neighbor chassisObservation, partners []chassisObservation) (ChassisCandidate, bool) {
	best := ChassisCandidate{}
	for _, partner := range partners {
		if partner.mac == neighbor.mac {
			continue
		}
		confidence, evidence := scoreChassisCandidate(neighbor, partner)
		// A shared vendor prefix alone is far too common in a /40 block; keep a
		// candidate only when at least one additional observable signal agrees.
		if confidence < 0.70 || confidence <= best.Confidence {
			continue
		}
		best = ChassisCandidate{
			NeighborMAC:  neighbor.mac,
			NeighborName: firstNonEmpty(neighbor.systemName, neighbor.name),
			PartnerMAC:   partner.mac,
			PartnerIP:    partner.ip,
			PartnerName:  partner.name,
			Confidence:   confidence,
			Evidence:     evidence,
		}
	}
	return best, best.Confidence > 0
}

func scoreChassisCandidate(neighbor, partner chassisObservation) (float64, []string) {
	confidence := 0.55
	evidence := []string{"同厂商前缀 " + neighbor.mac[:14]}
	if distance := macTailDistance(neighbor.mac, partner.mac); distance >= 0 && distance <= 3 {
		confidence += 0.15
		evidence = append(evidence, fmt.Sprintf("MAC 相邻（末字节差 %d）", distance))
	}
	switch partner.deviceType {
	case "gateway":
		confidence += 0.15
		evidence = append(evidence, "对端已识别为网关")
	case "router":
		confidence += 0.15
		evidence = append(evidence, "对端已识别为路由器")
	}
	if token := sharedVendorToken(neighbor.systemName+" "+neighbor.server+" "+neighbor.description, partner.name+" "+partner.server); token != "" {
		confidence += 0.10
		evidence = append(evidence, "同系统标识 "+token)
	}
	if confidence > 0.9 {
		confidence = 0.9
	}
	return math.Round(confidence*100) / 100, evidence
}

func macTailDistance(a, b string) int {
	if len(a) < 17 || len(b) < 17 {
		return -1
	}
	left, leftErr := parseHexByte(a[15:17])
	right, rightErr := parseHexByte(b[15:17])
	if leftErr != nil || rightErr != nil {
		return -1
	}
	distance := left - right
	if distance < 0 {
		distance = -distance
	}
	return distance
}

func parseHexByte(raw string) (int, error) {
	var value int
	_, err := fmt.Sscanf(raw, "%02x", &value)
	return value, err
}

var chassisVendorStopwords = map[string]bool{
	"upnp": true, "http": true, "https": true, "linux": true, "server": true,
	"device": true, "system": true, "root": true, "open": true, "wrt": true,
	"miniupnpd": true,
}

func sharedVendorToken(a, b string) string {
	left := vendorTokens(a)
	right := vendorTokens(b)
	for _, x := range left {
		for _, y := range right {
			if x == y || strings.HasPrefix(x, y) || strings.HasPrefix(y, x) {
				return x
			}
		}
	}
	return ""
}

func vendorTokens(raw string) []string {
	fields := strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(field) >= 4 && !chassisVendorStopwords[field] {
			tokens = append(tokens, field)
		}
	}
	return tokens
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
