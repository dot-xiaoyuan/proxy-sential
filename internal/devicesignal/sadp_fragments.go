package devicesignal

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"
)

// SADP responses observed on 204 use two IPv4 fragments (1480 and 147 UDP
// bytes). The router filter already admits later UDP fragments; keep only
// first-fragment-confirmed SADP datagrams and a short, bounded reassembly.
const (
	maxSADPDatagramBytes = 8200 // UDP header plus the bounded XML body.
	maxSADPAssemblies    = 256
	sadpAssemblyLifetime = 5 * time.Second
)

type sadpFragmentKey struct {
	source, destination [4]byte
	id                  uint16
	mac                 [6]byte
	vlan                int
}

type sadpAssembly struct {
	bytes     []byte
	seen      []bool
	count     int
	last      int
	createdAt time.Time
}

// acceptSADPFragment reports whether the frame was fragmented IPv4 UDP. Such
// frames must bypass the ordinary protocol parser until the whole XML exists.
func (b *captureBucket) acceptSADPFragment(frame []byte) ([]controlSignal, bool) {
	ethernet, ok := parseEthernetFrame(frame)
	if !ok || ethernet.etherType != 0x0800 || len(ethernet.payload) < 20 || ethernet.payload[0]>>4 != 4 {
		return nil, false
	}
	ip := ethernet.payload
	ihl := int(ip[0]&15) * 4
	if ihl < 20 || len(ip) < ihl || ip[9] != 17 {
		return nil, false
	}
	flags := binary.BigEndian.Uint16(ip[6:8])
	offset := int(flags&0x1fff) * 8
	more := flags&0x2000 != 0
	if !more && offset == 0 {
		return nil, false
	}
	totalIP := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalIP < ihl || totalIP > len(ip) || offset+totalIP-ihl > maxSADPDatagramBytes || more && (totalIP-ihl)%8 != 0 {
		return nil, true
	}
	var key sadpFragmentKey
	copy(key.source[:], ip[12:16])
	copy(key.destination[:], ip[16:20])
	key.id = binary.BigEndian.Uint16(ip[4:6])
	key.mac, key.vlan = ethernet.source, ethernet.vlan
	now := time.Now()
	if now.Sub(b.lastSADPFragmentSweep) >= time.Second {
		for pending, assembly := range b.sadpFragments {
			if now.Sub(assembly.createdAt) > sadpAssemblyLifetime {
				delete(b.sadpFragments, pending)
			}
		}
		b.lastSADPFragmentSweep = now
	}
	part := ip[ihl:totalIP]
	if offset == 0 {
		if len(part) < 8 || binary.BigEndian.Uint16(part[:2]) != 37020 {
			return nil, true
		}
		length := int(binary.BigEndian.Uint16(part[4:6]))
		if length < 9 || length > maxSADPDatagramBytes || len(part) > length {
			return nil, true
		}
		if b.sadpFragments == nil {
			b.sadpFragments = make(map[sadpFragmentKey]*sadpAssembly)
		}
		if len(b.sadpFragments) >= maxSADPAssemblies {
			b.controlKeyDrops++
			return nil, true
		}
		b.sadpFragments[key] = &sadpAssembly{bytes: make([]byte, length), seen: make([]bool, length), createdAt: now}
	}
	assembly := b.sadpFragments[key]
	if assembly == nil || offset+len(part) > len(assembly.bytes) || now.Sub(assembly.createdAt) > sadpAssemblyLifetime {
		delete(b.sadpFragments, key)
		return nil, true
	}
	for index, value := range part {
		position := offset + index
		if assembly.seen[position] && assembly.bytes[position] != value {
			delete(b.sadpFragments, key)
			return nil, true
		}
		if !assembly.seen[position] {
			assembly.count++
			assembly.seen[position] = true
			assembly.bytes[position] = value
		}
	}
	if !more {
		assembly.last = offset + len(part)
	}
	if assembly.last != len(assembly.bytes) || assembly.count != len(assembly.bytes) {
		return nil, true
	}
	delete(b.sadpFragments, key)
	if !bytes.Equal(assembly.bytes[:2], []byte{0x90, 0x9c}) {
		return nil, true
	}
	signal, ok := parseSADP(ethernet, net.IP(key.source[:]).String(), net.IP(key.destination[:]).String(), assembly.bytes[8:])
	if !ok {
		return nil, true
	}
	return []controlSignal{signal}, true
}
