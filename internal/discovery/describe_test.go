package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

const igdDescription = `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>TL-WR842N</friendlyName><manufacturer>TP-Link</manufacturer>
<modelName>TL-WR842N</modelName><modelNumber>v5</modelNumber></device></root>`

func ssdpAnnouncement(location string) normalized.Event {
	return normalized.Event{SchemaVersion: "v1", EventID: "passive-gw", Type: "discovery", Source: "passive", Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Observer: map[string]any{"source_id": "p", "sensor_id": "n", "config_version": 1},
		Subject:  map[string]any{"site": "s", "domain": "d", "ip": "192.168.1.1", "mac": "00:11:22:33:44:77"},
		Payload:  map[string]any{"origin": "ssdp", "is_response": true, "ttl": 120, "usn": "uuid:gw", "device_type": "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "location": location}}
}

type describeFixture struct {
	fetches  int
	onLink   bool
	neighbor string
	body     string
	errs     []error
}

func (f *describeFixture) describer(t *testing.T) *Describer {
	d := NewDescriber(t.TempDir())
	d.OnLink = func(net.IP) bool { return f.onLink }
	d.Neighbor = func(net.IP) string { return f.neighbor }
	d.Fetch = func(_ context.Context, location, target string) ([]byte, error) {
		f.fetches++
		if len(f.errs) > 0 {
			err := f.errs[0]
			f.errs = f.errs[1:]
			if err != nil {
				return nil, err
			}
		}
		if err := ValidateXML([]byte(f.body)); err != nil {
			return nil, err
		}
		return []byte(f.body), nil
	}
	return d
}

func spooled(t *testing.T, d *Describer) []normalized.Event {
	entries, _ := filepath.Glob(filepath.Join(d.Spool, "*.json"))
	out := []normalized.Event{}
	for _, path := range entries {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var events []normalized.Event
		if err = json.Unmarshal(b, &events); err != nil {
			t.Fatal(err)
		}
		out = append(out, events...)
	}
	return out
}

func TestDescriberEnrichesOnLinkAnnouncerWithMatchingNeighbor(t *testing.T) {
	f := &describeFixture{onLink: true, neighbor: "00:11:22:33:44:77", body: igdDescription}
	d := f.describer(t)
	d.Describe(context.Background(), ssdpAnnouncement("http://192.168.1.1:1900/igd.xml"))
	events := spooled(t, d)
	if len(events) != 1 || d.Stats().Fetched != 1 {
		t.Fatalf("description not spooled: %+v %+v", events, d.Stats())
	}
	o, err := FromEvent(events[0])
	if err != nil || o.Manufacturer != "TP-Link" || o.ModelName != "TL-WR842N v5" || o.Name != "TL-WR842N" || o.DeviceType != "gateway" || o.Confidence != "clue" || o.MAC != "00:11:22:33:44:77" {
		t.Fatalf("enriched observation wrong: %+v %v", o, err)
	}
	d.Offer(events[0])
	if d.Describe(context.Background(), ssdpAnnouncement("http://192.168.1.1:1900/igd.xml")); f.fetches != 1 {
		t.Fatal("same USN and location fetched twice")
	}
}

func TestDescriberRefusesUnreachableOrForeignAddresses(t *testing.T) {
	f := &describeFixture{onLink: false, neighbor: "00:11:22:33:44:77", body: igdDescription}
	d := f.describer(t)
	d.Describe(context.Background(), ssdpAnnouncement("http://192.168.1.1:1900/igd.xml"))
	if f.fetches != 0 || d.Stats().NotOnLink != 1 {
		t.Fatal("off-link private address was requested from the worker network")
	}
	f.onLink = true
	d.Describe(context.Background(), ssdpAnnouncement("http://192.168.1.9/igd.xml"))
	if f.fetches != 0 {
		t.Fatal("location host different from the announcer was requested")
	}
	f.neighbor = "00:aa:bb:cc:dd:ee"
	other := ssdpAnnouncement("http://192.168.1.1:1900/igd.xml")
	other.Payload["usn"] = "uuid:other"
	d.Describe(context.Background(), other)
	if f.fetches != 1 || len(spooled(t, d)) != 0 || d.Stats().MACMismatch != 1 {
		t.Fatal("description from a different device at the same address was kept")
	}
}

func TestDescriberRetriesOnceAndRejectsUnsafeBodies(t *testing.T) {
	f := &describeFixture{onLink: true, neighbor: "00:11:22:33:44:77", body: igdDescription, errs: []error{errors.New("timeout"), errors.New("timeout")}}
	d := f.describer(t)
	d.Describe(context.Background(), ssdpAnnouncement("http://192.168.1.1/a.xml"))
	if f.fetches != 2 || d.Stats().Failed != 1 || len(spooled(t, d)) != 0 {
		t.Fatalf("timeout handling wrong: fetches=%d %+v", f.fetches, d.Stats())
	}
	for index, body := range []string{"not xml at all <", `<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><root><device><modelName>&y;</modelName></device></root>`, "<root>" + strings.Repeat("x", 1<<20) + "</root>", "<root><device></device></root>"} {
		f.body = body
		e := ssdpAnnouncement("http://192.168.1.1/a.xml")
		e.Payload["usn"] = "uuid:body-" + string(rune('a'+index))
		d.Describe(context.Background(), e)
		if len(spooled(t, d)) != 0 {
			t.Fatalf("unsafe or empty description %d accepted", index)
		}
	}
}

func TestDescriberOfferSkipsUnattributableAnnouncements(t *testing.T) {
	d := NewDescriber(t.TempDir())
	noMAC := ssdpAnnouncement("http://192.168.1.1/a.xml")
	noMAC.Subject["mac"] = ""
	withdrawn := ssdpAnnouncement("http://192.168.1.1/a.xml")
	withdrawn.Payload["withdrawn"] = true
	d.Offer(noMAC)
	d.Offer(withdrawn)
	if len(d.queue) != 0 {
		t.Fatal("announcement without hardware identity or withdrawn service queued")
	}
	for index := 0; index < 300; index++ {
		d.Offer(ssdpAnnouncement("http://192.168.1.1/a.xml"))
	}
	if d.Stats().Dropped != 300-cap(d.queue) {
		t.Fatalf("full queue blocked or lost count: %+v", d.Stats())
	}
}
