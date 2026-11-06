package store

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

// passiveLivePTRFactRow is a compact, current-only projection of a responder's
// own multicast PTR advertisement. The original event remains in ClickHouse.
type passiveLivePTRFactRow struct {
	SensorID      string    `json:"sensor_id"`
	Site          string    `json:"site"`
	InterfaceName string    `json:"interface_name"`
	ResponderIP   string    `json:"responder_ip"`
	EndpointID    string    `json:"endpoint_id"`
	RecordName    string    `json:"record_name"`
	Instance      string    `json:"instance"`
	Name          string    `json:"name"`
	EventID       string    `json:"event_id"`
	ObservedAt    time.Time `json:"observed_at"`
	ValidUntil    time.Time `json:"valid_until"`
	Withdrawn     bool      `json:"withdrawn"`
}

func passiveLivePTRFact(event normalized.Event, scope passiveDiscoveryScope) (passiveLivePTRFactRow, bool) {
	if event.EventID == "" || event.Source != "zeek" || event.SourceEventType != "mdns" ||
		passiveString(event.Payload, "is_response") != "true" ||
		!strings.EqualFold(passiveString(event.Payload, "record_type"), "PTR") ||
		event.Payload["l2_source_mac_direct"] != true {
		return passiveLivePTRFactRow{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil || at.After(time.Now().Add(2*time.Minute)) {
		return passiveLivePTRFactRow{}, false
	}
	destination, err := netip.ParseAddr(passiveString(event.Flow, "dst_ip"))
	if err != nil || !destination.IsMulticast() {
		return passiveLivePTRFactRow{}, false
	}
	sensor := passiveString(event.Observer, "sensor_id")
	iface := passiveInterface(event)
	ip := passiveString(event.Subject, "ip")
	if passiveString(event.Flow, "src_ip") != ip {
		return passiveLivePTRFactRow{}, false
	}
	mac := validPassiveMAC(passiveString(event.Payload, "responder_l2_mac"))
	recordName := strings.ToLower(strings.TrimSuffix(passiveString(event.Payload, "record_name"), "."))
	instance := strings.TrimSuffix(passiveString(event.Payload, "service_target"), ".")
	if sensor == "" || iface == "" || !scope.allows(ip) || mac == "" || recordName == "" || instance == "" ||
		len(recordName) > 255 || len(instance) > 512 ||
		!strings.HasSuffix(strings.ToLower(instance), "."+recordName) {
		return passiveLivePTRFactRow{}, false
	}
	name := normalizeDeviceName(strings.TrimSpace(strings.Split(instance, "._")[0]))
	if name == "" {
		return passiveLivePTRFactRow{}, false
	}
	ttl := passiveTTL(event.Payload, 120)
	site := passiveString(event.Subject, "campus_id")
	if site == "" {
		site = sensor
	}
	return passiveLivePTRFactRow{
		SensorID: sensor, Site: site, InterfaceName: iface, ResponderIP: ip,
		EndpointID: "mac:" + mac, RecordName: recordName, Instance: strings.ToLower(instance), Name: name,
		EventID: event.EventID, ObservedAt: at, ValidUntil: at.Add(time.Duration(ttl) * time.Second), Withdrawn: ttl == 0,
	}, true
}

func passiveLivePTRKey(f passiveLivePTRFactRow) string {
	return strings.Join([]string{f.SensorID, f.Site, f.InterfaceName, f.ResponderIP, f.EndpointID, f.RecordName, f.Instance}, "\x00")
}

// ClickHouse is read by receive position, so a late old event can arrive after
// a newer withdrawal. Choose the latest event time for each semantic key.
func passiveLatestLivePTRFacts(facts []passiveLivePTRFactRow) []passiveLivePTRFactRow {
	latest := make(map[string]passiveLivePTRFactRow)
	for _, fact := range facts {
		key := passiveLivePTRKey(fact)
		prior, exists := latest[key]
		if !exists || fact.ObservedAt.After(prior.ObservedAt) ||
			(fact.ObservedAt.Equal(prior.ObservedAt) && fact.EventID > prior.EventID) {
			latest[key] = fact
		}
	}
	keys := make([]string, 0, len(latest))
	for key := range latest {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]passiveLivePTRFactRow, 0, len(keys))
	for _, key := range keys {
		result = append(result, latest[key])
	}
	return result
}
