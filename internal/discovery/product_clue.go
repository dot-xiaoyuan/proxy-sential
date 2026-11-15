package discovery

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

// IPProductClue records what a verified response endpoint self-reported. It is
// not a hardware identity, an address lease, or a confirmed-device count.
type IPProductClue struct {
	IP                string                       `json:"ip"`
	SensorID          string                       `json:"sensor_id"`
	Site              string                       `json:"site"`
	Domain            string                       `json:"domain"`
	VLAN              string                       `json:"vlan,omitempty"`
	VRF               string                       `json:"vrf,omitempty"`
	Type              string                       `json:"type,omitempty"`
	Manufacturer      string                       `json:"manufacturer,omitempty"`
	Model             string                       `json:"model,omitempty"`
	ProductStatus     string                       `json:"product_status"`
	Attribution       string                       `json:"attribution"`
	ObservedAt        time.Time                    `json:"observed_at"`
	EventID           string                       `json:"event_id"`
	RuleVersion       string                       `json:"rule_version"`
	SourceSHA256      string                       `json:"source_sha256,omitempty"`
	Sources           []fingerprint.HardwareSource `json:"sources,omitempty"`
	RawRef            map[string]any               `json:"raw_ref,omitempty"`
	MissingFields     []string                     `json:"missing_fields,omitempty"`
	EvaluationError   string                       `json:"evaluation_error,omitempty"`
	ConflictingTypes  []string                     `json:"conflicting_types,omitempty"`
	ConflictingModels []string                     `json:"conflicting_models,omitempty"`
}

// BuildIPProductClue runs during bounded materialization or controlled repair,
// never in the list reader. Current endpoint attribution is intentionally
// separate from the physical-MAC gate in HardwareFactFromObservation.
func BuildIPProductClue(o Observation, now time.Time) (*IPProductClue, error) {
	attribution := IPProductAttribution(o)
	if attribution == "" || o.Withdrawn || net.ParseIP(o.IP) == nil || o.Node == "" || o.Site == "" || o.Domain == "" ||
		o.ObservedAt.IsZero() || o.ObservedAt.After(now) || o.EventID == "" ||
		(o.Evidence.EventID != "" && o.Evidence.EventID != o.EventID) ||
		(str(o.Evidence.Payload, "vlan") != "" && str(o.Evidence.Payload, "vlan") != o.VLAN) ||
		str(o.Evidence.Observer, "capture_scope_issue") != "" {
		return nil, nil
	}
	signals, err := hardwareObservationSignals(o)
	if err != nil {
		return nil, err
	}
	// Only the response IP is verified here. Reuse the product matcher with
	// that endpoint's evidence, but do not create or enqueue a HardwareFact.
	evidence := (HardwareFact{Signals: signals, EvidenceID: o.EventID, ObservedAt: o.ObservedAt}).Evidence()
	result := fingerprint.EvaluateHardware(fingerprint.HardwareInput{IdentityTrusted: true, Evidence: evidence}, now)
	if result.Incomplete {
		return nil, fmt.Errorf("incomplete IP product evaluation: %s", result.Error)
	}
	clue := &IPProductClue{IP: o.IP, SensorID: o.Node, Site: o.Site, Domain: o.Domain, VLAN: o.VLAN, VRF: o.VRF,
		Type: result.Type, Manufacturer: result.Manufacturer, Model: result.Model, ProductStatus: result.TypeStatus,
		Attribution: attribution, ObservedAt: o.ObservedAt, EventID: o.EventID, RuleVersion: result.Version,
		Sources: result.Sources, RawRef: o.Evidence.RawRef, ConflictingTypes: result.ConflictingTypes, ConflictingModels: result.ConflictingModels}
	if clue.ProductStatus == "" || clue.ProductStatus == "candidate" {
		clue.ProductStatus = "no_type_match"
	}
	if len(signals) == 0 {
		clue.ProductStatus = "missing_product_fields"
		clue.MissingFields = []string{"system_object_id", "system_description", "product_model"}
		if o.Origin == "sip" || o.Origin == "rtsp" {
			clue.MissingFields = []string{"user_agent"}
		}
	}
	if clue.Manufacturer == "" {
		oid := str(o.Evidence.Payload, "system_object_id")
		if vendor, _, ok := fingerprint.LookupSNMPVendor(oid); ok {
			clue.Manufacturer = vendor
			clue.Sources = append(clue.Sources, fingerprint.HardwareSource{Source: "snmp_enterprise", RuleID: oid,
				RuleVersion: fingerprint.SNMPOIDVersion(), EvidenceID: o.EventID, ObservedAt: o.ObservedAt,
				Fields: map[string]string{"manufacturer": vendor}})
		}
	}
	if raw, err := json.Marshal(clue); err != nil || len(raw) > 16384 {
		return nil, fmt.Errorf("IP product result exceeds 16 KiB bound")
	}
	return clue, nil
}

// IPProductAttribution verifies which protocol endpoint owns the product
// field. A SIP client self-report proves neither its MAC nor an address lease.
func IPProductAttribution(o Observation) string {
	p := o.Evidence.Payload
	if o.Origin == "snmp" && p["is_response"] == true && str(p, "response_source_ip") == o.IP {
		return "response_ip"
	}
	if (o.Origin != "sip" && o.Origin != "rtsp") || o.IP == "" || o.IP != str(o.Evidence.Flow, "src_ip") ||
		str(o.Evidence.Flow, "direction") != "client" || str(p, "method") == "" || str(p, "user_agent") == "" ||
		o.EventID == "zeek-e3b0c44298fc1c149afbf4c8" {
		return ""
	}
	if o.Origin == "rtsp" {
		switch str(p, "method") {
		case "OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN", "GET_PARAMETER", "SET_PARAMETER", "ANNOUNCE", "RECORD":
		default:
			return ""
		}
	}
	digest, err := hex.DecodeString(str(o.Evidence.RawRef, "content_sha256"))
	if err != nil || len(digest) != 32 || o.Evidence.Source != "zeek" || o.EventID != "zeek-"+hex.EncodeToString(digest)[:24] {
		return ""
	}
	return "request_ip"
}
