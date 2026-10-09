package store

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/idna"

	"proxy-sentinel/internal/normalized"
)

// DomainObservation is the collector-independent input to device ecosystem
// recognition. It intentionally contains only normalized event fields.
type DomainObservation struct {
	EventID           string `json:"event_id"`
	Timestamp         string `json:"timestamp"`
	Domain            string `json:"domain"`
	EventSource       string `json:"event_source"`
	IP                string `json:"ip,omitempty"`
	EndpointID        string `json:"endpoint_id,omitempty"`
	AuthSessionID     string `json:"auth_session_id,omitempty"`
	AttributionMethod string `json:"attribution_method,omitempty"`
	SensorID          string `json:"sensor_id,omitempty"`
	CampusID          string `json:"campus_id,omitempty"`
}

// ExtractDomainObservation accepts only the four standard event shapes used by
// ecosystem recognition. Encrypted DNS/ECH events without an observable domain
// are deliberately ignored.
func ExtractDomainObservation(event normalized.Event) (DomainObservation, bool) {
	if isInfrastructureEntityRole(stringFromMap(event.Subject, "entity_role")) {
		return DomainObservation{}, false
	}
	field := ""
	switch strings.ToLower(strings.TrimSpace(event.Type)) {
	case "dns":
		field = "query"
	case "http":
		field = "host"
	case "tls", "quic":
		field = "sni"
	default:
		return DomainObservation{}, false
	}
	domain, err := NormalizeDomain(stringFromMap(event.Payload, field))
	if err != nil || domain == "" {
		return DomainObservation{}, false
	}
	endpointID := strings.TrimSpace(stringFromMap(event.Subject, "endpoint_id"))
	method := ""
	if endpointID != "" {
		method = "explicit_endpoint"
	}
	return DomainObservation{
		EventID: event.EventID, Timestamp: event.Timestamp, Domain: domain,
		EventSource: strings.ToLower(strings.TrimSpace(event.Type)),
		IP:          firstNonEmpty(stringFromMap(event.Subject, "ip"), stringFromMap(event.Flow, "src_ip")),
		EndpointID:  endpointID, AuthSessionID: stringFromMap(event.Payload, "session_id"),
		AttributionMethod: method,
		SensorID:          stringFromMap(event.Observer, "sensor_id"),
		CampusID:          firstNonEmpty(stringFromMap(event.Subject, "campus_id"), stringFromMap(event.Payload, "campus_id")),
	}, true
}

// AttributeDomainObservation follows the product attribution order for the
// explicit endpoint and active-session stages. Identity-history fallback is
// implemented by the production resolver and must also return a unique result.
func AttributeDomainObservation(ctx context.Context, observation DomainObservation, resolver IdentityAttributionResolver) (DomainObservation, bool, error) {
	if observation.EndpointID != "" {
		return observation, true, nil
	}
	if resolver == nil || observation.IP == "" || observation.Timestamp == "" {
		return observation, false, nil
	}
	// Prefer scoped passive device ownership without manufacturing account attribution.
	if scoped, ok := resolver.(interface {
		ResolveDeviceAt(context.Context, DomainObservation) (IdentityAttribution, bool, error)
	}); ok {
		item, found, err := scoped.ResolveDeviceAt(ctx, observation)
		if err != nil {
			return observation, false, err
		}
		if found {
			if item.Conflict {
				return observation, false, nil
			}
			observation.EndpointID = item.EndpointID
			observation.AttributionMethod = "dhcp_lease"
			return observation, true, nil
		}
		// Missing scope cannot authorize a fallback to an IP-only history join.
		return observation, false, nil
	}
	attribution, found, err := resolver.ResolveIdentityAt(ctx, observation.IP, observation.Timestamp)
	if err != nil {
		return observation, false, err
	}
	if !found || attribution.Conflict || strings.TrimSpace(attribution.EndpointID) == "" {
		return observation, false, nil
	}
	observation.EndpointID = attribution.EndpointID
	observation.AuthSessionID = attribution.SessionID
	if attribution.SessionID != "" {
		observation.AttributionMethod = "active_auth_session"
	} else {
		observation.AttributionMethod = "identity_history"
	}
	return observation, true, nil
}

// NormalizeDomain canonicalizes DNS names without accepting URLs, paths or IP
// literals. Port stripping supports HTTP Host values including bracketed IPv6.
func NormalizeDomain(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "/\\?#@") {
		return "", fmt.Errorf("invalid domain")
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.Count(value, ":") == 1 {
		if index := strings.LastIndexByte(value, ':'); index > 0 {
			if port, portErr := strconv.Atoi(value[index+1:]); portErr == nil && port > 0 && port <= 65535 {
				value = value[:index]
			}
		}
	}
	value = strings.TrimSuffix(strings.Trim(value, "[]"), ".")
	if value == "" || net.ParseIP(value) != nil {
		return "", fmt.Errorf("invalid domain")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", fmt.Errorf("normalize IDNA domain: %w", err)
	}
	if len(ascii) > 253 {
		return "", fmt.Errorf("domain exceeds 253 bytes")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid domain label")
		}
	}
	return ascii, nil
}
