package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"proxy-sentinel/internal/normalized"
)

// Description is the self-reported UPnP device description. It stays a clue:
// it names hardware for display but never confirms the device role.
type Description struct {
	DeviceType   string `json:"device_type,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	ModelName    string `json:"model_name,omitempty"`
	ModelNumber  string `json:"model_number,omitempty"`
}

func ParseDescription(b []byte) (Description, error) {
	if e := ValidateXML(b); e != nil {
		return Description{}, e
	}
	var doc struct {
		Device struct {
			DeviceType   string `xml:"deviceType"`
			FriendlyName string `xml:"friendlyName"`
			Manufacturer string `xml:"manufacturer"`
			ModelName    string `xml:"modelName"`
			ModelNumber  string `xml:"modelNumber"`
		} `xml:"device"`
	}
	if e := xml.Unmarshal(b, &doc); e != nil {
		return Description{}, e
	}
	d := Description{DeviceType: cleanDescriptionText(doc.Device.DeviceType), FriendlyName: cleanDescriptionText(doc.Device.FriendlyName),
		Manufacturer: cleanDescriptionText(doc.Device.Manufacturer), ModelName: cleanDescriptionText(doc.Device.ModelName), ModelNumber: cleanDescriptionText(doc.Device.ModelNumber)}
	if d == (Description{}) {
		return d, errors.New("description has no device fields")
	}
	return d, nil
}

func cleanDescriptionText(v string) string {
	v = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, v))
	if len([]rune(v)) > 128 {
		v = string([]rune(v)[:128])
	}
	return v
}

type DescribeStats struct {
	Fetched, NotOnLink, MACMismatch, Failed, Dropped int
}

// Describer reads LOCATION descriptions off the capture path. A private address
// such as 192.168.1.1 seen on a mirror port usually belongs to a network the
// worker cannot reach, and the worker's own network may hold a different device
// at the same address, so a description is only kept when the address is on-link
// and the neighbor table maps it to the MAC that sent the announcement.
type Describer struct {
	Spool    string
	Fetch    func(ctx context.Context, location, target string) ([]byte, error)
	OnLink   func(net.IP) bool
	Neighbor func(net.IP) string
	Interval time.Duration
	Now      func() time.Time

	queue chan normalized.Event
	once  sync.Once
	mu    sync.Mutex
	seen  map[string]time.Time
	stats DescribeStats
}

func NewDescriber(spool string) *Describer {
	return &Describer{Spool: spool, Fetch: ReadDescription, OnLink: onLinkAddress, Neighbor: neighborMAC, Interval: 100 * time.Millisecond, Now: time.Now}
}

func (d *Describer) init() {
	d.once.Do(func() {
		d.queue = make(chan normalized.Event, 256)
		d.seen = map[string]time.Time{}
	})
}

// Offer never blocks the spool drain; a full queue drops the event and counts it.
func (d *Describer) Offer(e normalized.Event) {
	if d == nil || str(e.Payload, "origin") != "ssdp" || str(e.Payload, "location") == "" || e.Payload["withdrawn"] == true || str(e.Subject, "mac") == "" {
		return
	}
	if _, described := e.Payload["description"]; described {
		return
	}
	d.init()
	select {
	case d.queue <- e:
	default:
		d.mu.Lock()
		d.stats.Dropped++
		d.mu.Unlock()
	}
}

func (d *Describer) Stats() DescribeStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

func (d *Describer) Run(ctx context.Context) {
	d.init()
	tick := time.NewTicker(d.Interval)
	defer tick.Stop()
	report := time.NewTicker(10 * time.Minute)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-report.C:
			s := d.Stats()
			log.Printf("ssdp describe: fetched=%d not_on_link=%d mac_mismatch=%d failed=%d dropped=%d", s.Fetched, s.NotOnLink, s.MACMismatch, s.Failed, s.Dropped)
		case e := <-d.queue:
			if d.Describe(ctx, e) {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
			}
		}
	}
}

// Describe returns true when a network request was attempted, so Run can pace requests.
func (d *Describer) Describe(ctx context.Context, e normalized.Event) bool {
	d.init()
	location, ip, mac := str(e.Payload, "location"), net.ParseIP(str(e.Subject, "ip")), str(e.Subject, "mac")
	u, err := url.Parse(location)
	if ip == nil || ip.To4() == nil || err != nil || u.Hostname() != ip.String() {
		return false
	}
	now := d.Now()
	key := str(e.Payload, "usn") + "|" + location + "|" + mac
	d.mu.Lock()
	for k, until := range d.seen {
		if !until.After(now) {
			delete(d.seen, k)
		}
	}
	if until, ok := d.seen[key]; ok && until.After(now) || len(d.seen) >= 10000 {
		d.mu.Unlock()
		return false
	}
	ttl := time.Duration(number(e.Payload, "ttl")) * time.Second
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	d.seen[key] = now.Add(ttl)
	d.mu.Unlock()
	if !d.OnLink(ip) {
		d.count(func(s *DescribeStats) { s.NotOnLink++ })
		return false
	}
	var body []byte
	for attempt := 0; attempt < 2; attempt++ {
		if body, err = d.Fetch(ctx, location, ip.String()); err == nil || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		d.count(func(s *DescribeStats) { s.Failed++ })
		return true
	}
	if !strings.EqualFold(d.Neighbor(ip), mac) {
		d.count(func(s *DescribeStats) { s.MACMismatch++ })
		return true
	}
	desc, err := ParseDescription(body)
	if err != nil {
		d.count(func(s *DescribeStats) { s.Failed++ })
		return true
	}
	if err = d.writeEnriched(e, desc); err != nil {
		d.count(func(s *DescribeStats) { s.Failed++ })
		return true
	}
	d.count(func(s *DescribeStats) { s.Fetched++ })
	return true
}

func (d *Describer) count(f func(*DescribeStats)) {
	d.mu.Lock()
	f(&d.stats)
	d.mu.Unlock()
}

func (d *Describer) writeEnriched(e normalized.Event, desc Description) error {
	enriched := e
	enriched.Payload = map[string]any{}
	for k, v := range e.Payload {
		enriched.Payload[k] = v
	}
	enriched.Payload["description"] = desc
	if desc.FriendlyName != "" {
		enriched.Payload["name"] = desc.FriendlyName
	}
	h := sha256.Sum256([]byte(e.EventID + ":described"))
	enriched.EventID = "passive-described-" + hex.EncodeToString(h[:16])
	b, err := json.Marshal([]normalized.Event{enriched})
	if err != nil {
		return err
	}
	path := filepath.Join(d.Spool, hex.EncodeToString(h[:16])+".json")
	if err = os.WriteFile(path+".tmp", b, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func onLinkAddress(ip net.IP) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if n, ok := addr.(*net.IPNet); ok && n.Contains(ip) && !n.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
