package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

// DiscoveryHandshakeClue is an IP-scoped weak clue from mirror traffic. A
// shared or reassigned address does not identify one physical device.
type DiscoveryHandshakeClue struct {
	Kind       string    `json:"kind"`
	Value      string    `json:"value"`
	ObservedAt time.Time `json:"observed_at"`
	EvidenceID string    `json:"evidence_id"`
}

type DiscoveryHandshakeClueReader interface {
	DiscoveryHandshakeClues(context.Context, SharedObservationScope, time.Time) ([]DiscoveryHandshakeClue, error)
}

// Detail reads one current IP and an 11-minute indexed search window. Bodies
// are resolved through the verified archive reference; list reads stay on the
// current projection and never scan this history.
func (s *DBStore) DiscoveryHandshakeClues(ctx context.Context, scope SharedObservationScope, now time.Time) ([]DiscoveryHandshakeClue, error) {
	if s == nil || scope.SensorID == "" || scope.CampusID == "" || scope.AccessDomain == "" || now.IsZero() {
		return nil, errors.New("invalid discovery handshake scope")
	}
	ip, err := netip.ParseAddr(scope.IP)
	if err != nil {
		return nil, err
	}
	scope.IP = ip.String()
	cutover, active, err := s.activeStreamSharedCutover(ctx, scope.SensorID, "handshake-sidecar")
	if err != nil {
		return nil, err
	}
	if !active {
		return []DiscoveryHandshakeClue{}, nil
	}
	from := now.UTC().Add(-11 * time.Minute)
	if from.Before(cutover.Cutoff) {
		from = cutover.Cutoff
	}
	if !from.Before(now) {
		return []DiscoveryHandshakeClue{}, nil
	}
	rows, _, err := s.readStreamSharedRows(ctx, scope, cutover.ScopeID, "handshake-sidecar", cutover.Epoch, scope.IP, from, now.UTC())
	if err != nil {
		return nil, err
	}
	return extractDiscoveryHandshakeClues(rows, scope.IP, from, now.UTC())
}

func extractDiscoveryHandshakeClues(rows []sharedObservationEvent, ip string, from, now time.Time) ([]DiscoveryHandshakeClue, error) {
	byValue := map[string]DiscoveryHandshakeClue{}
	for _, row := range rows {
		if row.IP != ip || row.EventID == "" {
			continue
		}
		var payload struct {
			Schema  string                         `json:"handshake_schema"`
			Samples []sharedaccess.HandshakeSample `json:"feature_samples"`
		}
		if err := json.Unmarshal([]byte(row.Payload), &payload); err != nil {
			return nil, err
		}
		if payload.Schema != "handshake-samples/v1" {
			continue
		}
		for _, sample := range payload.Samples {
			value := strings.TrimSpace(sample.Value)
			if sample.EventID == "" || sample.ObservedAt.Before(from) || sample.ObservedAt.After(now) || value == "" {
				continue
			}
			kind := sample.Family
			switch kind {
			case "user_agent":
				if len(value) > 256 {
					value = value[:256]
				}
			case "ja3":
				if len(value) != 32 {
					continue
				}
				if _, err := hex.DecodeString(value); err != nil {
					continue
				}
				value = strings.ToLower(value)
			case "ja4":
				if !sharedaccess.ValidJA4TLS(value) {
					continue
				}
			default:
				continue
			}
			key := kind + "\x00" + value
			if prior, ok := byValue[key]; !ok || sample.ObservedAt.After(prior.ObservedAt) {
				byValue[key] = DiscoveryHandshakeClue{Kind: kind, Value: value, ObservedAt: sample.ObservedAt.UTC(), EvidenceID: row.EventID}
			}
		}
	}
	items := make([]DiscoveryHandshakeClue, 0, len(byValue))
	for _, clue := range byValue {
		items = append(items, clue)
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].ObservedAt.Equal(items[j].ObservedAt) {
			return items[i].ObservedAt.After(items[j].ObservedAt)
		}
		return items[i].Kind+items[i].Value < items[j].Kind+items[j].Value
	})
	if len(items) > 12 {
		items = items[:12]
	}
	return items, nil
}
