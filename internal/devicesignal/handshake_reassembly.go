package devicesignal

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"slices"
	"time"
)

const (
	maxHelloRecord     = 16384 + 5 // TLSPlaintext length plus the record header
	maxHelloFlights    = 64
	maxHelloCandidates = 512
	helloFlightTimeout = 3 * time.Second
)

type helloFlow struct {
	outlet            handshakeKey
	destination       netip.Addr
	port, vlan, outer uint16
}

type helloSegment struct {
	flow helloFlow
	seq  uint32
	data []byte
	ttl  uint8
}

func parseHelloSegment(frame []byte) (helloSegment, bool) {
	eth, ok := parseEthernetFrame(frame)
	ip := eth.payload
	if !ok || eth.etherType != 0x0800 || len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != 6 || binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
		return helloSegment{}, false
	}
	h := int(ip[0]&15) * 4
	end := int(binary.BigEndian.Uint16(ip[2:4]))
	if h < 20 || end < h+20 || end > len(ip) {
		return helloSegment{}, false
	} // socket clipping is not a TCP segment boundary
	tcp := ip[h:end]
	t := int(tcp[12]>>4) * 4
	if binary.BigEndian.Uint16(tcp[2:4]) != 443 || tcp[13]&6 != 0 || t < 20 || t >= len(tcp) {
		return helloSegment{}, false
	}
	return helloSegment{flow: helloFlow{outlet: handshakeKey{IP: netip.AddrFrom4([4]byte(ip[12:16])), MAC: eth.source}, destination: netip.AddrFrom4([4]byte(ip[16:20])), port: binary.BigEndian.Uint16(tcp[:2]), vlan: eth.innerVLAN, outer: eth.outerVLAN}, seq: binary.BigEndian.Uint32(tcp[4:8]), data: tcp[t:], ttl: ip[8]}, true
}

type helloFirstID struct {
	flow   helloFlow
	seq    uint32
	digest [32]byte
}

func (s helloSegment) firstID() helloFirstID {
	return helloFirstID{s.flow, s.seq, sha256.Sum256(s.data)}
}

// A short first segment may end inside the record header. When enough bytes
// are present the declared length bounds the allocation and excludes trailers.
func (s helloSegment) splitHelloSize() (int, bool) {
	p := s.data
	if p[0] != 22 || (len(p) > 1 && p[1] != 3) || (len(p) > 5 && p[5] != 1) {
		return 0, false
	}
	if len(p) < 5 {
		return maxHelloRecord, true
	}
	n := 5 + int(binary.BigEndian.Uint16(p[3:5]))
	return n, n > len(p) && n >= 9
}

type helloFlight struct {
	id      helloFirstID
	started time.Time
	data    []byte
	seen    []byte // one bit per byte for out-of-order, duplicate and conflicting overlap checks
	prefix  int
}

type helloReassemblyStats struct {
	Deduplicated      int    `json:"redundant_candidates"`
	FeatureOmitted    int    `json:"feature_omitted"`
	FilteredOutlets   int    `json:"filtered_outlets"`
	UnfilteredOutlets int    `json:"uncovered_outlets"`
	KernelStatsKnown  bool   `json:"kernel_stats_known"`
	Received          uint64 `json:"received_packets"`
	Dropped           uint64 `json:"dropped_packets"`
	Started           int    `json:"started"`
	Recovered         int    `json:"recovered"`
	Oversize          int    `json:"over_size"`
	Capacity          int    `json:"capacity_drops"`
	Expired           int    `json:"timeouts"`
	Incomplete        int    `json:"incomplete"`
	Conflicts         int    `json:"conflicts"`
	Unpaired          int    `json:"unpaired"`
}

type helloReassembly struct {
	active     map[helloFlow]*helloFlight
	anchors    map[helloFirstID]handshakeFeatureObservation
	completed  map[helloFirstID]handshakeFeatureObservation
	nextExpiry time.Time
	stats      helloReassemblyStats
}

// Only a truncated observation on the original capture socket can acquire
// features. Its activity, VLAN conflict, metadata and count stay untouched.
func (r *helloReassembly) anchor(frame []byte, obs handshakeObservation) {
	s, ok := parseHelloSegment(frame)
	if !ok {
		return
	}
	n, ok := s.splitHelloSize()
	if !ok || n > maxHelloRecord {
		return
	}
	id := s.firstID()
	if _, found := r.anchors[id]; found {
		return
	}
	if len(r.anchors) >= maxHelloCandidates {
		r.stats.Capacity++
		return
	}
	if r.anchors == nil {
		r.anchors = make(map[helloFirstID]handshakeFeatureObservation)
	}
	at := obs.ObservedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	r.anchors[id] = handshakeFeatureObservation{observedAt: at, clientTTL: s.ttl, clientVLAN: s.flow.vlan, clientOuterVLAN: s.flow.outer, destinationPort: 443}
}

func (r *helloReassembly) expire(now time.Time) {
	for k, f := range r.active {
		if now.Sub(f.started) >= helloFlightTimeout {
			delete(r.active, k)
			r.stats.Expired++
		}
	}
	r.nextExpiry = now.Add(time.Second)
}

func (r *helloReassembly) consume(frame []byte, keys map[handshakeKey]struct{}, now time.Time) {
	s, ok := parseHelloSegment(frame)
	if !ok {
		return
	}
	if _, ok = keys[s.flow.outlet]; !ok {
		return
	}
	if !now.Before(r.nextExpiry) {
		r.expire(now)
	}
	f := r.active[s.flow]
	if f != nil && now.Sub(f.started) >= helloFlightTimeout {
		delete(r.active, s.flow)
		r.stats.Expired++
		f = nil
	}
	if f == nil || int32(s.seq-f.id.seq) < 0 || uint32(s.seq-f.id.seq) >= uint32(len(f.data)) {
		n, start := s.splitHelloSize()
		if !start {
			return
		}
		if n > maxHelloRecord {
			r.stats.Oversize++
			return
		}
		id := s.firstID()
		if _, done := r.completed[id]; done {
			return
		}
		if f != nil {
			r.stats.Incomplete++
		} else if len(r.active) >= maxHelloFlights {
			r.stats.Capacity++
			return
		}
		if r.active == nil {
			r.active = make(map[helloFlow]*helloFlight)
		}
		f = &helloFlight{id: id, started: now, data: make([]byte, n), seen: make([]byte, (n+7)/8)}
		r.active[s.flow] = f
		r.stats.Started++
	}
	offset := int(s.seq - f.id.seq)
	for j, b := range s.data[:min(len(s.data), len(f.data)-offset)] {
		i := offset + j
		bit := byte(1 << (i % 8))
		if f.seen[i/8]&bit != 0 && f.data[i] != b {
			delete(r.active, s.flow)
			r.stats.Conflicts++
			return
		}
		f.seen[i/8] |= bit
		f.data[i] = b
	}
	for f.prefix < len(f.data) && f.seen[f.prefix/8]&(1<<(f.prefix%8)) != 0 {
		f.prefix++
	}
	if f.prefix < 6 {
		return
	}
	n := 5 + int(binary.BigEndian.Uint16(f.data[3:5]))
	if n > maxHelloRecord || n > len(f.data) {
		delete(r.active, s.flow)
		r.stats.Oversize++
		return
	}
	if n < 9 || f.data[1] != 3 || f.data[5] != 1 {
		delete(r.active, s.flow)
		r.stats.Incomplete++
		return
	}
	if f.prefix < n {
		return
	}
	delete(r.active, s.flow)
	record := f.data[:n]
	ja3 := clientHelloJA3(record)
	if ja3 == "" {
		r.stats.Incomplete++
		return
	}
	if len(r.completed) >= maxHelloCandidates {
		r.stats.Capacity++
		return
	}
	if r.completed == nil {
		r.completed = make(map[helloFirstID]handshakeFeatureObservation)
	}
	// Same identity as an unsegmented TLS record (addresses, ports, original
	// TCP sequence number and exactly one record).
	var header [16]byte
	src, dst := s.flow.outlet.IP.As4(), s.flow.destination.As4()
	copy(header[:4], src[:])
	copy(header[4:8], dst[:])
	binary.BigEndian.PutUint16(header[8:10], s.flow.port)
	binary.BigEndian.PutUint16(header[10:12], 443)
	binary.BigEndian.PutUint32(header[12:], f.id.seq)
	h := sha256.New()
	h.Write(header[:])
	h.Write(record)
	r.completed[f.id] = handshakeFeatureObservation{ja3: ja3, ja4: clientHelloJA4Validated(record), eventID: hex.EncodeToString(h.Sum(nil)[:16])}
}

// Spend only the sample budget left after existing selected records. Raw TCP
// bytes never enter a summary, case, queue, or persisted document.
func (r *helloReassembly) apply(selected map[*handshakeSummary]bool, summaries map[handshakeKey]*handshakeSummary, budget int) {
	ids := make([]helloFirstID, 0, len(r.completed))
	for id := range r.completed {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b helloFirstID) int {
		return cmp.Compare(r.completed[a].eventID, r.completed[b].eventID)
	})
	for _, id := range ids {
		anchor, ok := r.anchors[id]
		s := summaries[id.flow.outlet]
		if !ok || s == nil || !selected[s] || s.truncated == 0 {
			r.stats.Unpaired++
			continue
		}
		feature := anchor
		got := r.completed[id]
		feature.eventID, feature.ja3, feature.ja4 = got.eventID, got.ja3, got.ja4
		omittedBefore := r.stats.FeatureOmitted
		added := s.storeFeature(feature, budget, &r.stats.FeatureOmitted)
		budget -= added
		if added > 0 {
			r.stats.Recovered++
		} else if r.stats.FeatureOmitted == omittedBefore {
			r.stats.Deduplicated++
		}
	}
	r.expire(time.Now())
	r.stats.Incomplete += len(r.active)
	r.active = nil
	r.anchors = nil
	r.completed = nil
}
