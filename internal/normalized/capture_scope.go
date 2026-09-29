package normalized

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"
)

// CaptureScope is a controlled collector binding, not data supplied by packets.
// ValidFrom prevents a new mapping from assigning earlier captured traffic.
type CaptureScope struct {
	UserCIDRs           []string  `json:"user_cidrs,omitempty"`
	SchemaVersion       string    `json:"schema_version"`
	SensorID            string    `json:"sensor_id"`
	CollectorInstanceID string    `json:"collector_instance_id"`
	CampusID            string    `json:"campus_id"`
	AccessDomain        string    `json:"access_domain"`
	ValidFrom           time.Time `json:"valid_from"`
	ValidUntil          time.Time `json:"valid_until"`
}

func LoadCaptureScope(path string) (*CaptureScope, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, fmt.Errorf("capture scope exceeds 64 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s CaptureScope
	if err = dec.Decode(&s); err != nil {
		return nil, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("trailing capture scope content")
	}
	if s.SchemaVersion != "capture-scope/v1" || s.ValidFrom.IsZero() || s.ValidUntil.IsZero() || !s.ValidUntil.After(s.ValidFrom) {
		return nil, fmt.Errorf("invalid capture scope version or validity interval")
	}
	for _, v := range []string{s.SensorID, s.CollectorInstanceID, s.CampusID, s.AccessDomain} {
		if v == "" || strings.TrimSpace(v) != v {
			return nil, fmt.Errorf("capture scope fields must be nonempty and trimmed")
		}
	}
	for _, cidr := range s.UserCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return nil, fmt.Errorf("capture user network must be an explicit canonical CIDR")
		}
	}
	return &s, nil
}
func (s *CaptureScope) Apply(event Event) Event {
	if s == nil {
		return event
	}
	clone := func(m map[string]any) map[string]any {
		n := make(map[string]any, len(m)+2)
		for k, v := range m {
			n[k] = v
		}
		return n
	}
	event.Observer = clone(event.Observer)
	event.Subject = clone(event.Subject)
	event.Payload = clone(event.Payload)
	fail := func(reason string) Event { event.Observer["capture_scope_issue"] = reason; return event }
	sensor, _ := event.Observer["sensor_id"].(string)
	instance, _ := event.Observer["collector_instance_id"].(string)
	if sensor != s.SensorID || instance != s.CollectorInstanceID {
		return fail("capture_scope_collector_mismatch")
	}
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil || at.Before(s.ValidFrom) || !at.Before(s.ValidUntil) {
		return fail("capture_scope_outside_validity")
	}
	campus, _ := event.Subject["campus_id"].(string)
	domain, _ := event.Payload["access_domain"].(string)
	if campus != "" && campus != s.CampusID || domain != "" && domain != s.AccessDomain {
		return fail("capture_scope_conflict")
	}
	raw, _ := json.Marshal(s)
	sum := sha256.Sum256(raw)
	event.Subject["campus_id"] = s.CampusID
	event.Payload["access_domain"] = s.AccessDomain
	event.Observer["capture_scope_id"] = hex.EncodeToString(sum[:16])
	return event
}

// Direction requires a controlled user-side network. Private addresses alone
// cannot prove direction at a mirrored interface.
func (s *CaptureScope) Direction(source, destination string) string {
	src, err := netip.ParseAddr(source)
	if err != nil {
		return "unknown"
	}
	dst, err := netip.ParseAddr(destination)
	if err != nil {
		return "unknown"
	}
	return s.DirectionAddr(src, dst)
}

// DirectionAddr is the allocation-free capture hot-path equivalent of
// Direction. Packet collectors already have binary addresses and must not
// stringify and parse every mirrored packet at hundreds of thousands pps.
func (s *CaptureScope) DirectionAddr(src, dst netip.Addr) string {
	if s == nil || len(s.UserCIDRs) == 0 || !src.IsValid() || !dst.IsValid() {
		return "unknown"
	}
	inSource, inDestination := false, false
	for _, cidr := range s.UserCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return "unknown"
		}
		inSource = inSource || prefix.Contains(src.Unmap())
		inDestination = inDestination || prefix.Contains(dst.Unmap())
	}
	if inSource && inDestination {
		return "internal"
	}
	if inSource {
		return "outbound"
	}
	if inDestination {
		return "inbound"
	}
	return "unknown"
}
