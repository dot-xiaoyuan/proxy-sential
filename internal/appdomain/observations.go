package appdomain

import (
	"encoding/json"
	"fmt"
	"math"
	"proxy-sentinel/internal/normalized"
	"sort"
	"strconv"
	"time"
)

type Observation struct {
	EventID       string  `json:"event_id"`
	Timestamp     string  `json:"timestamp"`
	SensorID      string  `json:"sensor_id"`
	CampusID      string  `json:"campus_id"`
	IP            string  `json:"ip"`
	ConnectionID  string  `json:"connection_id,omitempty"`
	EventType     string  `json:"event_type"`
	Domain        string  `json:"domain,omitempty"`
	SourceField   string  `json:"source_field,omitempty"`
	BundleVersion string  `json:"bundle_version"`
	Match         Match   `json:"match"`
	UploadBytes   *uint64 `json:"upload_bytes"`
	DownloadBytes *uint64 `json:"download_bytes"`
}

func text(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func number(m map[string]any, k string) *uint64 {
	var n uint64
	switch v := m[k].(type) {
	case float64:
		if v < 0 || v >= math.Exp2(64) || math.Trunc(v) != v {
			return nil
		}
		n = uint64(v)
	case uint64:
		n = v
	case int64:
		if v < 0 {
			return nil
		}
		n = uint64(v)
	case int:
		if v < 0 {
			return nil
		}
		n = uint64(v)
	case json.Number:
		x, err := strconv.ParseUint(string(v), 10, 64)
		if err != nil {
			return nil
		}
		n = x
	default:
		return nil
	}
	return &n
}
func Observe(e normalized.Event, b *Bundle) Observation {
	o := Observation{EventID: e.EventID, Timestamp: e.Timestamp, SensorID: text(e.Observer, "sensor_id"), CampusID: text(e.Subject, "campus_id"), IP: text(e.Subject, "ip"), ConnectionID: text(e.Flow, "connection_id"), EventType: e.Type, BundleVersion: "none", UploadBytes: number(e.Flow, "bytes_toserver"), DownloadBytes: number(e.Flow, "bytes_toclient")}
	if ts, err := time.Parse(time.RFC3339Nano, o.Timestamp); err == nil {
		o.Timestamp = ts.UTC().Format(time.RFC3339Nano)
	}
	if o.CampusID == "" {
		o.CampusID = text(e.Payload, "campus_id")
		if o.CampusID == "" {
			o.CampusID = text(e.Observer, "campus_id")
		}
	}
	if b != nil {
		o.BundleVersion = b.Manifest.Version
	}
	key := ""
	switch e.Type {
	case "dns":
		key = "query"
	case "http":
		key = "host"
	case "tls", "quic":
		key = "sni"
	}
	if key != "" {
		o.SourceField = e.Type + "." + key
		raw := text(e.Payload, key)
		if d, err := NormalizeDomain(raw); err == nil {
			o.Domain = d
			o.Match = b.Match(d)
		}
	}
	return o
}
func (o Observation) Key() string { return o.SensorID + "\x00" + o.EventID }

type Query struct {
	From, To                              time.Time
	SensorID, CampusID, IP, ApplicationID string
}
type Item struct {
	ApplicationID           string  `json:"application_id"`
	Name                    string  `json:"name"`
	Category                string  `json:"category"`
	TerminalCount           int     `json:"terminal_count"`
	ConnectionCount         int     `json:"connection_count"`
	ObservationCount        int     `json:"observation_count"`
	UploadBytes             *uint64 `json:"upload_bytes"`
	DownloadBytes           *uint64 `json:"download_bytes"`
	MissingMeterConnections int     `json:"missing_meter_connections"`
	LastSeen                string  `json:"last_seen"`
}
type Bucket struct {
	ConnectionCount         int     `json:"connection_count"`
	UploadBytes             *uint64 `json:"upload_bytes"`
	DownloadBytes           *uint64 `json:"download_bytes"`
	MissingMeterConnections int     `json:"missing_meter_connections"`
}
type Report struct {
	AsOf                          string         `json:"as_of,omitempty"`
	Items                         []Item         `json:"items"`
	Versions                      map[string]int `json:"versions"`
	DNSObservations               int            `json:"dns_observations"`
	UnknownObservations           int            `json:"unknown_observations"`
	MissingConnectionObservations int            `json:"missing_connection_observations"`
	Unknown                       Bucket         `json:"unknown"`
	MultiApplication              Bucket         `json:"multi_application"`
	ObservationCount              int            `json:"observation_count"`
	TrafficBasis                  string         `json:"traffic_basis"`
}

func eligible(o Observation, q Query) bool {
	t, err := time.Parse(time.RFC3339Nano, o.Timestamp)
	return err == nil && !t.Before(q.From) && t.Before(q.To) && (q.SensorID == "" || q.SensorID == o.SensorID) && (q.CampusID == "" || q.CampusID == o.CampusID) && (q.IP == "" || q.IP == o.IP)
}
func sum(a **uint64, b *uint64) {
	if b == nil {
		return
	}
	if *a == nil {
		v := *b
		*a = &v
	} else {
		**a += *b
	}
}
func maximum(a **uint64, b *uint64) {
	if b != nil && (*a == nil || **a < *b) {
		v := *b
		*a = &v
	}
}

type connection struct {
	apps         map[string]bool
	up, down     *uint64
	active       bool
	observations []Observation
}

const ClassifiedTrafficBasis = "仅汇总已被特征库识别的应用连接累计字节；未分类域名保留在观测统计中，不进入连接流量合计"

func Aggregate(observations []Observation, q Query) Report {
	r := Report{Items: []Item{}, Versions: map[string]int{}, TrafficBasis: ClassifiedTrafficBasis}
	seen := map[string]bool{}
	cs := map[string]*connection{}
	items := map[string]*Item{}
	terminals := map[string]map[string]bool{}
	add := func(o Observation) {
		id := o.Match.TargetID
		if items[id] == nil {
			items[id] = &Item{ApplicationID: id, Name: o.Match.Name, Category: o.Match.Category}
			terminals[id] = map[string]bool{}
		}
		it := items[id]
		it.ObservationCount++
		if o.IP != "" {
			terminals[id][o.CampusID+"\x00"+o.IP] = true
		}
		if o.Timestamp > it.LastSeen {
			it.LastSeen = o.Timestamp
		}
	}
	for _, o := range observations {
		tm, err := time.Parse(time.RFC3339Nano, o.Timestamp)
		if err != nil || !tm.Before(q.To) {
			continue
		}
		if seen[o.Key()] {
			continue
		}
		seen[o.Key()] = true
		active := eligible(o, q)
		if active {
			r.ObservationCount++
			r.Versions[o.BundleVersion]++
			if o.EventType == "dns" {
				r.DNSObservations++
			}
			if o.Domain != "" && o.Match.TargetID == "" {
				r.UnknownObservations++
			}
			if o.EventType != "dns" && o.ConnectionID == "" {
				r.MissingConnectionObservations++
			}
			if o.Match.TargetType == "application" {
				add(o)
			}
		}
		if o.EventType == "dns" || o.ConnectionID == "" {
			continue
		}
		key := o.SensorID + "\x00" + o.CampusID + "\x00" + o.ConnectionID
		c := cs[key]
		if c == nil {
			c = &connection{apps: map[string]bool{}}
			cs[key] = c
		}
		c.active = c.active || active
		c.observations = append(c.observations, o)
		maximum(&c.up, o.UploadBytes)
		maximum(&c.down, o.DownloadBytes)
		if o.Match.TargetType == "application" {
			c.apps[o.Match.TargetID] = true
		}
	}
	for _, c := range cs {
		if !c.active {
			continue
		}
		if len(c.apps) == 0 {
			// Preserve unclassified observation counts above, while matching the
			// database read model's application-only traffic accounting contract.
			continue
		}
		if len(c.apps) != 1 {
			bucket := &r.Unknown
			if len(c.apps) > 1 {
				bucket = &r.MultiApplication
			}
			bucket.ConnectionCount++
			sum(&bucket.UploadBytes, c.up)
			sum(&bucket.DownloadBytes, c.down)
			if c.up == nil || c.down == nil {
				bucket.MissingMeterConnections++
			}
			continue
		}
		for id := range c.apps {
			if items[id] == nil {
				for _, o := range c.observations {
					if o.Match.TargetType == "application" && o.Match.TargetID == id {
						items[id] = &Item{ApplicationID: id, Name: o.Match.Name, Category: o.Match.Category}
						terminals[id] = map[string]bool{}
						break
					}
				}
			}
			it := items[id]
			for _, o := range c.observations {
				if eligible(o, q) {
					if o.IP != "" {
						terminals[id][o.CampusID+"\x00"+o.IP] = true
					}
					if o.Timestamp > it.LastSeen {
						it.LastSeen = o.Timestamp
					}
				}
			}
			it.ConnectionCount++
			sum(&it.UploadBytes, c.up)
			sum(&it.DownloadBytes, c.down)
			if c.up == nil || c.down == nil {
				it.MissingMeterConnections++
			}
		}
	}
	for id, it := range items {
		it.TerminalCount = len(terminals[id])
		if q.ApplicationID == "" || q.ApplicationID == id {
			r.Items = append(r.Items, *it)
		}
	}
	sort.Slice(r.Items, func(i, j int) bool {
		if r.Items[i].ConnectionCount != r.Items[j].ConnectionCount {
			return r.Items[i].ConnectionCount > r.Items[j].ConnectionCount
		}
		return r.Items[i].ApplicationID < r.Items[j].ApplicationID
	})
	return r
}

type UnknownDomain struct {
	Domain           string `json:"domain"`
	SourceField      string `json:"source_field"`
	FirstSeen        string `json:"first_seen"`
	LastSeen         string `json:"last_seen"`
	ObservationCount int    `json:"observation_count"`
	SensorID         string `json:"sensor_id"`
	BundleVersion    string `json:"bundle_version"`
}

func UnknownDomains(obs []Observation, q Query) []UnknownDomain {
	m := map[string]*UnknownDomain{}
	seen := map[string]bool{}
	for _, o := range obs {
		if !eligible(o, q) || o.Domain == "" || o.Match.TargetID != "" || seen[o.Key()] {
			continue
		}
		seen[o.Key()] = true
		k := fmt.Sprintf("%s|%s|%s|%s", o.Domain, o.SourceField, o.SensorID, o.BundleVersion)
		v := m[k]
		if v == nil {
			v = &UnknownDomain{Domain: o.Domain, SourceField: o.SourceField, FirstSeen: o.Timestamp, LastSeen: o.Timestamp, SensorID: o.SensorID, BundleVersion: o.BundleVersion}
			m[k] = v
		}
		v.ObservationCount++
		if o.Timestamp < v.FirstSeen {
			v.FirstSeen = o.Timestamp
		}
		if o.Timestamp > v.LastSeen {
			v.LastSeen = o.Timestamp
		}
	}
	out := []UnknownDomain{}
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, *m[k])
	}
	return out
}
