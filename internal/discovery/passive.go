package discovery

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/textproto"
	"proxy-sentinel/internal/normalized"
	"strconv"
	"strings"
	"time"
)

// DecodeFrame never attributes a service to its querying or relay device.
type cachedDNS struct {
	record  dnsmessage.Resource
	expires time.Time
	at      time.Time
}
type DNSCache struct{ records map[string]cachedDNS }

func DecodeFrame(frame []byte, source Source, at time.Time) []normalized.Event {
	return decodeFrame(frame, source, at, nil)
}
func decodeServiceFrame(frame []byte, source Source, at time.Time, cache *DNSCache) []normalized.Event {
	if len(frame) < 14 {
		return nil
	}
	ether := binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	senderMAC := ""
	if mac := net.HardwareAddr(frame[6:12]); mac[0]&1 == 0 && !bytes.Equal(mac, make([]byte, 6)) {
		senderMAC = mac.String()
	}
	vlan := ""
	for ether == 0x8100 || ether == 0x88a8 {
		if len(frame) < offset+4 {
			return nil
		}
		tag := strconv.Itoa(int(binary.BigEndian.Uint16(frame[offset:offset+2]) & 4095))
		if vlan != "" {
			vlan += "/"
		}
		vlan += tag
		ether = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	emit := func(kind, key, ip, mac string, payload map[string]any) normalized.Event {
		h := sha256.Sum256(append(append([]byte(source.ID+":"+key+":"+at.Format(time.RFC3339Nano)), frame...), byte(0)))
		payload["origin"] = kind
		payload["ethernet_source_mac"] = senderMAC
		return normalized.Event{SchemaVersion: "v1", EventID: "passive-" + hex.EncodeToString(h[:16]), Type: "discovery", Confidence: 0.5, Flow: map[string]any{"src_ip": "", "dst_ip": "", "proto": "other", "direction": "unknown"}, Source: "passive", SourceEventType: kind, Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"source_id": source.ID, "sensor_id": source.Node, "config_version": source.ConfigVersion, "interface": source.Address}, Subject: map[string]any{"site": source.Site, "domain": source.Domain, "vlan": vlan, "ip": ip, "mac": mac}, Payload: payload}
	}
	if ether == 0x88cc {
		data := frame[offset:]
		p := map[string]any{"location_kind": "neighbor"}
		haveChassis, havePort, haveTTL := false, false, false
		managementIP := ""
		for len(data) >= 2 {
			h := binary.BigEndian.Uint16(data[:2])
			typ, length := h>>9, int(h&511)
			data = data[2:]
			if len(data) < length {
				return nil
			}
			v := data[:length]
			data = data[length:]
			switch typ {
			case 0:
				data = nil
			case 1:
				if length > 1 {
					p["chassis_id"] = hex.EncodeToString(v)
					haveChassis = true
				}
			case 2:
				if length > 1 {
					p["remote_port"] = string(v[1:])
					havePort = true
				}
			case 3:
				if length == 2 {
					p["ttl"] = int(binary.BigEndian.Uint16(v))
					haveTTL = true
				}
			case 5:
				p["name"] = string(v)
			case 8:
				if length >= 6 && v[0] == 5 && v[1] == 1 {
					managementIP = net.IP(v[2:6]).String()
				}
				if length >= 18 && v[0] == 17 && v[1] == 2 {
					managementIP = net.IP(v[2:18]).String()
				}
			case 7:
				if length == 4 {
					p["system_capabilities"] = int(binary.BigEndian.Uint16(v[2:]))
				}
			}
		}
		if !haveChassis || !havePort || !haveTTL {
			return nil
		}
		return []normalized.Event{emit("lldp", str(p, "chassis_id"), managementIP, "", p)}
	}
	var src net.IP
	var udp []byte
	if ether == 0x0800 {
		if len(frame) < offset+20 || frame[offset]>>4 != 4 {
			return nil
		}
		ihl := int(frame[offset]&15) * 4
		total := int(binary.BigEndian.Uint16(frame[offset+2 : offset+4]))
		if ihl < 20 || total < ihl+8 || len(frame) < offset+total || frame[offset+9] != 17 || binary.BigEndian.Uint16(frame[offset+6:offset+8])&0x3fff != 0 {
			return nil
		}
		src = net.IP(frame[offset+12 : offset+16])
		udp = frame[offset+ihl : offset+total]
	} else if ether == 0x86dd {
		if len(frame) < offset+48 || frame[offset]>>4 != 6 || frame[offset+6] != 17 {
			return nil
		}
		length := int(binary.BigEndian.Uint16(frame[offset+4 : offset+6]))
		if length < 8 || len(frame) < offset+40+length {
			return nil
		}
		src = net.IP(frame[offset+8 : offset+24])
		udp = frame[offset+40 : offset+40+length]
	} else {
		return nil
	}
	if len(udp) < 8 {
		return nil
	}
	sport, dport := binary.BigEndian.Uint16(udp[:2]), binary.BigEndian.Uint16(udp[2:4])
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if length < 8 || length > len(udp) {
		return nil
	}
	body := udp[8:length]
	if sport == 1900 || dport == 1900 {
		if len(body) > 16384 {
			return nil
		}
		reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(body)))
		line, e := reader.ReadLine()
		if e != nil || (!strings.HasPrefix(line, "HTTP/1.1 200") && !strings.HasPrefix(line, "NOTIFY * HTTP/1.1")) {
			return nil
		}
		h, e := reader.ReadMIMEHeader()
		if e != nil {
			return nil
		}
		ttl := 0
		for _, v := range strings.Split(h.Get("Cache-Control"), ",") {
			k, n, ok := strings.Cut(strings.TrimSpace(v), "=")
			if ok && strings.EqualFold(k, "max-age") {
				ttl, _ = strconv.Atoi(strings.Trim(n, "\""))
			}
		}
		withdraw := h.Get("Nts") == "ssdp:byebye"
		if ttl <= 0 && !withdraw {
			return nil
		}
		if ttl > 604800 {
			ttl = 604800
		}
		return []normalized.Event{emit("ssdp", h.Get("Usn"), src.String(), "", map[string]any{"is_response": true, "ttl": ttl, "withdrawn": withdraw, "usn": h.Get("Usn"), "service_type": firstText(h.Get("St"), h.Get("Nt")), "device_type": h.Get("Nt"), "location": h.Get("Location")})}
	}
	if sport == 547 || dport == 547 {
		bindings, withdrawn, err := ParseDHCPv6(body)
		if err != nil {
			return nil
		}
		out := []normalized.Event{}
		for _, binding := range bindings {
			p := map[string]any{"origin": "dhcpv6", "is_response": true, "ttl": int(binding.Valid), "withdrawn": withdrawn, "duid": binding.DUID, "service_instance": binding.DUID + ":" + binding.IAID}
			out = append(out, emit("dhcpv6", binding.IP, binding.IP, "", p))
		}
		return out
	}
	if sport == 5355 || sport == 137 {
		var msg dnsmessage.Message
		if msg.Unpack(body) != nil || !msg.Header.Response {
			return nil
		}
		out := []normalized.Event{}
		kind := "llmnr"
		if sport == 137 {
			kind = "nbns"
		}
		for _, rr := range msg.Answers {
			ip := ""
			switch v := rr.Body.(type) {
			case *dnsmessage.AResource:
				ip = net.IP(v.A[:]).String()
			case *dnsmessage.AAAAResource:
				ip = net.IP(v.AAAA[:]).String()
			case *dnsmessage.UnknownResource:
				if sport == 137 && rr.Header.Type == 32 && len(v.Data) >= 6 {
					ip = net.IP(v.Data[2:6]).String()
				}
			}
			if ip == "" {
				continue
			}
			out = append(out, emit(kind, ip, ip, "", map[string]any{"origin": kind, "is_response": true, "ttl": int(min(rr.Header.TTL, 604800)), "name": discoveryResponseName(kind, rr.Header.Name.String())}))
		}
		return out
	}
	if sport == 3702 || dport == 3702 {
		p, err := ParseWSDiscovery(string(body))
		if err != nil {
			return nil
		}
		return []normalized.Event{emit("ws_discovery", str(p, "endpoint_reference"), src.String(), "", p)}
	}
	if sport == 161 || sport == 162 {
		p, err := ParseSNMPResponse(body)
		if err != nil {
			return nil
		}
		return []normalized.Event{emit("snmp", str(p, "system_object_id"), src.String(), "", p)}
	}
	if sport == 47808 || dport == 47808 {
		p, err := ParseBACnetAnnouncement(body)
		if err != nil {
			return nil
		}
		return []normalized.Event{emit("bacnet", str(p, "device_identifier"), firstText(str(p, "announcer_ip"), src.String()), "", p)}
	}
	if sport == 5683 {
		p, err := ParseCoAPResponse(body)
		if err != nil {
			return nil
		}
		return []normalized.Event{emit("coap", str(p, "resource_type"), src.String(), "", p)}
	}
	if sport != 5353 && dport != 5353 {
		return nil
	}
	var msg dnsmessage.Message
	if msg.Unpack(body) != nil || !msg.Header.Response {
		return nil
	}
	records := append(append(msg.Answers, msg.Authorities...), msg.Additionals...)
	touched := map[string]bool{}
	for _, r := range records {
		touched[strings.ToLower(r.Header.Name.String())] = true
	}
	if cache != nil {
		if cache.records == nil {
			cache.records = map[string]cachedDNS{}
		}
		scope := source.ID + "|" + source.Site + "|" + source.Domain + "|" + vlan + "|"
		for key, v := range cache.records {
			if !v.expires.After(at) {
				delete(cache.records, key)
			}
		}
		for _, r := range records {
			key := scope + r.Header.Name.String() + "|" + fmt.Sprint(r.Header.Type) + "|" + fmt.Sprint(r.Body)
			ttl := r.Header.TTL
			if ttl > 604800 {
				ttl = 604800
			}
			if ttl == 0 {
				delete(cache.records, key)
				continue
			}
			if len(cache.records) < 10000 {
				cache.records[key] = cachedDNS{r, at.Add(time.Duration(ttl) * time.Second), at}
			}
		}
		current := records
		records = nil
		for key, v := range cache.records {
			if strings.HasPrefix(key, scope) && !v.at.After(at) {
				r := v.record
				r.Header.TTL = uint32(v.expires.Sub(at) / time.Second)
				records = append(records, r)
			}
		}
		// Preserve explicit withdrawals even though removed from the live cache.
		for _, r := range current {
			if r.Header.TTL == 0 {
				records = append(records, r)
			}
		}
	}
	addresses := map[string][]string{}
	addressTTL := map[string]uint32{}
	txt := map[string][]string{}
	ptr := map[string]string{}
	for _, r := range records {
		key := strings.ToLower(r.Header.Name.String())
		switch v := r.Body.(type) {
		case *dnsmessage.AResource:
			addresses[key] = append(addresses[key], net.IP(v.A[:]).String())
			addressTTL[key+"|"+net.IP(v.A[:]).String()] = r.Header.TTL
		case *dnsmessage.AAAAResource:
			addresses[key] = append(addresses[key], net.IP(v.AAAA[:]).String())
			addressTTL[key+"|"+net.IP(v.AAAA[:]).String()] = r.Header.TTL
		case *dnsmessage.TXTResource:
			txt[key] = v.TXT
		case *dnsmessage.PTRResource:
			ptr[strings.ToLower(v.PTR.String())] = key
		}
	}
	result := []normalized.Event{}
	for i, r := range records {
		srv, ok := r.Body.(*dnsmessage.SRVResource)
		if !ok {
			continue
		}
		name := strings.ToLower(r.Header.Name.String())
		if !touched[name] && !touched[strings.ToLower(srv.Target.String())] {
			continue
		}
		service := ptr[name]
		if service == "" {
			parts := strings.Split(name, ".")
			for j := 0; j+1 < len(parts); j++ {
				if strings.HasPrefix(parts[j], "_") && (parts[j+1] == "_tcp" || parts[j+1] == "_udp") {
					service = parts[j] + "." + parts[j+1]
					break
				}
			}
		}
		service = strings.TrimSuffix(strings.TrimSuffix(service, "."), ".local")
		ips := addresses[strings.ToLower(srv.Target.String())]
		if len(ips) == 0 {
			ips = []string{""}
		}
		for _, ip := range ips {
			// Cached or proxied records may describe another host; only the sender's own address gets its MAC.
			mac := ""
			if ip != "" && ip == src.String() {
				// Transport MAC is not a client identity binding.
				mac = ""
			}
			ttl := r.Header.TTL
			if a, ok := addressTTL[strings.ToLower(srv.Target.String())+"|"+ip]; ok && a < ttl {
				ttl = a
			}
			if ttl > 604800 {
				ttl = 604800
			}
			result = append(result, emit("dns_sd", fmt.Sprint(i, ":", ip), ip, mac, map[string]any{"is_response": true, "ttl": int(ttl), "service_type": service, "service_instance": r.Header.Name.String(), "service_target": srv.Target.String(), "service_port": int(srv.Port), "txt": txt[name]}))
		}
	}
	return result
}

func firstText(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
