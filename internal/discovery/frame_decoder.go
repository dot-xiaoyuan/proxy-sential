package discovery

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"proxy-sentinel/internal/devicesignal"
	"proxy-sentinel/internal/normalized"
	"strings"
	"time"
)

func decodeFrame(frame []byte, source Source, at time.Time, cache *DNSCache) []normalized.Event {
	events := decodeServiceFrame(frame, source, at, cache)
	if len(events) > 0 {
		return events
	}
	for _, c := range devicesignal.DecodeDiscoveryControls(frame) {
		ttl := 600
		if c.Kind == "lldp" || c.Kind == "cdp" {
			ttl = 120
		}
		p := c.Payload
		p["origin"] = c.Kind
		if _, ok := p["ttl"]; !ok {
			p["ttl"] = ttl
		}
		if c.Kind == "arp" {
			p["address_binding"] = str(p, "message") == "reply"
		}
		if c.Kind == "ndp" {
			off, ether := ethernetOffset(frame)
			if ether != 0x86dd || len(frame) < off+64 || frame[off+7] != 255 {
				continue
			}
			body := frame[off+40:]
			if body[1] != 0 {
				continue
			}
			c.MAC = ""
			p["address_binding"] = false
			if body[0] == 136 && net.IP(body[8:24]).String() == c.IP {
				for at := 24; at+2 <= len(body); {
					size := int(body[at+1]) * 8
					if size == 0 || at+size > len(body) {
						break
					}
					if body[at] == 2 && size == 8 {
						m := net.HardwareAddr(body[at+2 : at+8])
						if m[0]&1 == 0 && m.String() != "00:00:00:00:00:00" {
							c.MAC = m.String()
							p["address_binding"] = true
						}
					}
					at += size
				}
			}
		}
		// ARP queries may contain a legitimate sender binding, but never a binding
		// for the requested target. NDP solicitation is retained as a clue only.
		sum := sha256.Sum256(append([]byte(source.ID+at.Format(time.RFC3339Nano)), frame...))
		events = append(events, normalized.Event{SchemaVersion: "v1", EventID: "passive-" + hex.EncodeToString(sum[:16]), Type: "discovery", Source: "passive", SourceEventType: c.Kind, Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": source.Node, "source_id": source.ID, "interface": source.Address}, Subject: map[string]any{"site": source.Site, "domain": source.Domain, "vlan": fmt.Sprint(c.VLAN), "ip": c.IP, "mac": c.MAC}, Payload: p, Confidence: .5})
	}
	return events
}

type fragmentGroup struct {
	at          time.Time
	header      []byte
	pieces      map[int][]byte
	total, size int
	offset      int
	ipv6        bool
}
type FrameDecoder struct {
	DNS           DNSCache
	fragments     map[string]*fragmentGroup
	FragmentDrops uint64
}

// Decode bounds fragment memory to 256 datagrams and 64 KiB each, with a
// 10-second lifetime. Overlapping fragments are rejected rather than guessed.
func (d *FrameDecoder) Decode(frame []byte, source Source, at time.Time) []normalized.Event {
	prepared := d.prepare(frame, at)
	if prepared == nil {
		return nil
	}
	return decodeFrame(prepared, source, at, &d.DNS)
}
func ethernetOffset(frame []byte) (int, uint16) {
	if len(frame) < 14 {
		return 0, 0
	}
	off, kind := 14, binary.BigEndian.Uint16(frame[12:14])
	for tags := 0; (kind == 0x8100 || kind == 0x88a8) && tags < 2; tags++ {
		if len(frame) < off+4 {
			return 0, 0
		}
		kind = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	return off, kind
}
func (d *FrameDecoder) prepare(frame []byte, at time.Time) []byte {
	off, kind := ethernetOffset(frame)
	if off == 0 {
		return nil
	}
	if kind == 0x0800 {
		if len(frame) < off+20 {
			return nil
		}
		ihl := int(frame[off]&15) * 4
		total := int(binary.BigEndian.Uint16(frame[off+2 : off+4]))
		if ihl < 20 || total < ihl || len(frame) < off+total {
			return nil
		}
		flags := binary.BigEndian.Uint16(frame[off+6 : off+8])
		if flags&0x3fff == 0 {
			return frame
		}
		if frame[off+9] != 17 {
			return nil
		}
		key := fmt.Sprintf("%x|%x", frame[:off], frame[off+4:off+6]) + "|" + net.IP(frame[off+12:off+16]).String() + "|" + net.IP(frame[off+16:off+20]).String()
		return d.fragment(key, frame[:off+ihl], frame[off+ihl:off+total], int(flags&0x1fff)*8, flags&0x2000 != 0, off, false, at)
	}
	if kind != 0x86dd {
		return frame
	}
	if len(frame) < off+40 {
		return nil
	}
	end := off + 40 + int(binary.BigEndian.Uint16(frame[off+4:off+6]))
	if end > len(frame) {
		return nil
	}
	next, pos := frame[off+6], off+40
	for n := 0; n < 8; n++ {
		switch next {
		case 0, 43, 60:
			if pos+2 > end {
				return nil
			}
			length := (int(frame[pos+1]) + 1) * 8
			if pos+length > end {
				return nil
			}
			next = frame[pos]
			pos += length
		case 44:
			if pos+8 > end || frame[pos] != 17 {
				return nil
			}
			fragment := binary.BigEndian.Uint16(frame[pos+2 : pos+4])
			key := fmt.Sprintf("%x|%x|%x", frame[:off], frame[off+8:off+40], frame[pos+4:pos+8])
			header := append([]byte(nil), frame[:off+40]...)
			header[off+6] = 17
			return d.fragment(key, header, frame[pos+8:end], int(fragment&0xfff8), fragment&1 != 0, off, true, at)
		default:
			if pos == off+40 {
				return frame
			}
			out := append([]byte(nil), frame[:off+40]...)
			out[off+6] = next
			out = append(out, frame[pos:end]...)
			binary.BigEndian.PutUint16(out[off+4:off+6], uint16(len(out)-off-40))
			return out
		}
	}
	return nil
}
func (d *FrameDecoder) fragment(key string, header, payload []byte, start int, more bool, off int, v6 bool, at time.Time) []byte {
	if d.fragments == nil {
		d.fragments = map[string]*fragmentGroup{}
	}
	for k, g := range d.fragments {
		if at.Sub(g.at) > 10*time.Second {
			delete(d.fragments, k)
			d.FragmentDrops++
		}
	}
	reject := func() []byte { delete(d.fragments, key); d.FragmentDrops++; return nil }
	if start+len(payload) > 65535 || len(payload) == 0 || more && len(payload)%8 != 0 {
		return reject()
	}
	g := d.fragments[key]
	if g == nil {
		if len(d.fragments) >= 256 {
			d.FragmentDrops++
			return nil
		}
		g = &fragmentGroup{at: at, pieces: map[int][]byte{}, total: -1, offset: off, ipv6: v6}
		d.fragments[key] = g
	}
	for offset, part := range g.pieces {
		if start < offset+len(part) && offset < start+len(payload) {
			return reject()
		}
	}
	g.pieces[start] = append([]byte(nil), payload...)
	g.size += len(payload)
	if start == 0 {
		g.header = append([]byte(nil), header...)
	}
	if !more {
		g.total = start + len(payload)
	}
	if g.total < 0 || g.size != g.total || len(g.header) == 0 {
		return nil
	}
	out := append([]byte(nil), g.header...)
	for pos := 0; pos < g.total; {
		part, ok := g.pieces[pos]
		if !ok {
			return nil
		}
		out = append(out, part...)
		pos += len(part)
	}
	delete(d.fragments, key)
	if v6 {
		binary.BigEndian.PutUint16(out[off+4:off+6], uint16(g.total))
	} else {
		if len(out)-off > 65535 {
			return reject()
		}
		binary.BigEndian.PutUint16(out[off+2:off+4], uint16(len(out)-off))
		out[off+6] = 0
		out[off+7] = 0
	}
	return out
}
func packetProtocol(frame []byte) string {
	off, kind := ethernetOffset(frame)
	if off == 0 {
		return "malformed"
	}
	switch kind {
	case 0x0806:
		return "arp"
	case 0x88cc:
		return "lldp"
	case 0x893a:
		return "ieee1905_client_association"
	}
	pos := off
	if kind == 0x0800 {
		if len(frame) < pos+20 {
			return "malformed"
		}
		if frame[pos+9] != 17 {
			return "other"
		}
		pos += int(frame[pos]&15) * 4
	} else if kind == 0x86dd {
		if len(frame) < pos+40 {
			return "malformed"
		}
		if frame[pos+6] == 58 {
			return "ndp"
		}
		if frame[pos+6] != 17 {
			return "ipv6_extensions"
		}
		pos += 40
	} else {
		return "other"
	}
	if len(frame) < pos+4 {
		return "malformed"
	}
	a, b := binary.BigEndian.Uint16(frame[pos:pos+2]), binary.BigEndian.Uint16(frame[pos+2:pos+4])
	for _, p := range []struct {
		port uint16
		name string
	}{{5353, "dns_sd"}, {1900, "ssdp"}, {3702, "ws_discovery"}, {161, "snmp"}, {162, "snmp"}, {5683, "coap"}, {47808, "bacnet"}, {546, "dhcpv6"}, {547, "dhcpv6"}, {137, "nbns"}, {5355, "llmnr"}} {
		if a == p.port || b == p.port {
			return p.name
		}
	}
	return strings.ToLower("other")
}
