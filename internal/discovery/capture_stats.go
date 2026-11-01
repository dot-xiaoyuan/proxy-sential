package discovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type ProtocolCaptureStats struct {
	Received  uint64 `json:"received"`
	Parsed    uint64 `json:"parsed"`
	Rejected  uint64 `json:"rejected"`
	Eligible  uint64 `json:"eligible"`
	Coalesced uint64 `json:"coalesced"`
}

// These are observations of the bounded capture channel, not counts of
// durable input. A consumer may drain between observations, so the peak is
// explicitly sampled. Queue overflow remains visible after later draining.
type CaptureQueueStats struct {
	Batches             int    `json:"batches"`
	Capacity            int    `json:"capacity"`
	PeakObservedBatches int    `json:"peak_observed_batches"`
	FullCount           uint64 `json:"full_count"`
}

// DNS cache admission failures do not mean a packet was dropped: current
// message records still participate in decoding. Counters are cumulative per
// capture process; only the last affected DNS message hash is retained.
type DNSCacheRecordKinds struct {
	A    uint64 `json:"a"`
	AAAA uint64 `json:"aaaa"`
	PTR  uint64 `json:"ptr"`
	SRV  uint64 `json:"srv"`
	TXT  uint64 `json:"txt"`
}

type DNSCacheCaptureStats struct {
	Records                        int                 `json:"records"`
	Bytes                          int                 `json:"bytes"`
	RecordsNotRetained             uint64              `json:"records_not_retained"`
	MessagesWithRecordsNotRetained uint64              `json:"messages_with_records_not_retained"`
	NotRetainedByRecordLimit       DNSCacheRecordKinds `json:"not_retained_by_record_limit"`
	NotRetainedByByteLimit         DNSCacheRecordKinds `json:"not_retained_by_byte_limit"`
	LastMessageSHA256              string              `json:"last_message_sha256,omitempty"`
}

type CaptureStats struct {
	DNSRecordEvidenceVersion int                              `json:"dns_record_evidence_version"`
	EventKeyVersion          int                              `json:"event_key_version"`
	Config                   CollectionConfig                 `json:"config"`
	StartedAt                time.Time                        `json:"started_at"`
	UpdatedAt                time.Time                        `json:"updated_at"`
	Protocols                map[string]*ProtocolCaptureStats `json:"protocols"`
	FragmentDrops            uint64                           `json:"fragment_drops"`
	Eligible                 uint64                           `json:"eligible"`
	Coalesced                uint64                           `json:"coalesced"`
	DNSCache                 DNSCacheCaptureStats             `json:"dns_cache"`
	Queue                    CaptureQueueStats                `json:"capture_queue"`
}

var DiscoveryCaptureProtocols = []string{"dns_sd", "ssdp", "ws_discovery", "snmp", "arp", "ndp", "lldp", "cdp", "ieee1905_client_association", "dhcpv6", "nbns", "llmnr", "bacnet", "coap"}

func NewCaptureStats() *CaptureStats {
	s := &CaptureStats{DNSRecordEvidenceVersion: 1, EventKeyVersion: 1, StartedAt: time.Now().UTC(), Protocols: map[string]*ProtocolCaptureStats{}}
	for _, p := range DiscoveryCaptureProtocols {
		s.Protocols[p] = &ProtocolCaptureStats{}
	}
	return s
}
func (s *CaptureStats) record(protocol string, n int) {
	p := s.Protocols[protocol]
	if p == nil {
		p = &ProtocolCaptureStats{}
		s.Protocols[protocol] = p
	}
	p.Received++
	if n > 0 {
		p.Parsed += uint64(n)
	} else {
		p.Rejected++
	}
}
func (s *CaptureStats) recordEligible(protocol string, coalesced bool) {
	p := s.Protocols[protocol]
	if p == nil {
		p = &ProtocolCaptureStats{}
		s.Protocols[protocol] = p
	}
	s.Eligible++
	p.Eligible++
	if coalesced {
		s.Coalesced++
		p.Coalesced++
	}
}
func (s *CaptureStats) persist(dir string) error {
	s.UpdatedAt = time.Now().UTC()
	return s.persistSnapshot(dir)
}

func (s *CaptureStats) recordQueue(batches, capacity int, full bool) {
	s.Queue.Batches, s.Queue.Capacity = batches, capacity
	if batches > s.Queue.PeakObservedBatches {
		s.Queue.PeakObservedBatches = batches
	}
	if full {
		s.Queue.FullCount++
	}
}

// Delayed writes must retain the observation time; a slow filesystem cannot
// turn a stale capture heartbeat into a fresh one.
func (s *CaptureStats) persistSnapshot(dir string) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "capture.stats")
	if err = os.WriteFile(path+".tmp", raw, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
func (r Repository) UpdateCaptureRuntime(ctx context.Context, dir, sensor string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "capture.stats"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var stats CaptureStats
	if err = json.Unmarshal(raw, &stats); err != nil {
		return err
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	owners := append([]ProtocolOwner(nil), stats.Config.Protocols...)
	sort.Slice(owners, func(i, j int) bool { return owners[i].Protocol < owners[j].Protocol })
	for _, owner := range owners {
		protocol := owner.Protocol
		if owner.Source != "discovery-worker" {
			continue
		}
		p := stats.Protocols[protocol]
		if p == nil {
			p = &ProtocolCaptureStats{}
		}
		message := ""
		if time.Since(stats.UpdatedAt) > 5*time.Second {
			message = "capture_heartbeat_stale"
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO discovery_protocol_runtime(sensor_id,protocol,enabled,received,parsed,rejected,last_seen,error,updated_at) VALUES($1,$2,$8,$3,$4,$5,CASE WHEN $3::bigint>0 THEN $6::timestamptz ELSE NULL END,$7,$6) ON CONFLICT(sensor_id,protocol) DO UPDATE SET enabled=EXCLUDED.enabled,received=EXCLUDED.received,parsed=EXCLUDED.parsed,rejected=EXCLUDED.rejected,last_seen=EXCLUDED.last_seen,error=EXCLUDED.error,updated_at=EXCLUDED.updated_at`, sensor, protocol, p.Received, p.Parsed, p.Rejected, stats.UpdatedAt, message, owner.Enabled)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r Repository) ConfigureProtocolRuntime(ctx context.Context, sensor string, c CollectionConfig) error {
	for _, p := range c.Protocols {
		_, e := r.DB.ExecContext(ctx, `INSERT INTO discovery_protocol_runtime(sensor_id,protocol,owner,enabled) VALUES($1,$2,$3,$4) ON CONFLICT(sensor_id,protocol) DO UPDATE SET owner=EXCLUDED.owner,enabled=EXCLUDED.enabled`, sensor, p.Protocol, p.Source, p.Enabled)
		if e != nil {
			return e
		}
	}
	return nil
}
func (r Repository) SetMetadataProfileStatus(ctx context.Context, sensor string, e error) error {
	message := ""
	if e != nil {
		message = e.Error()
	}
	_, err := r.DB.ExecContext(ctx, `UPDATE discovery_protocol_runtime SET error=$2,updated_at=now() WHERE sensor_id=$1 AND owner='zeek' AND protocol<>'dhcp' AND enabled`, sensor, message)
	return err
}
