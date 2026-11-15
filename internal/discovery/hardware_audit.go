package discovery

import (
	"net"
	"proxy-sentinel/internal/fingerprint"
	"sort"
	"time"
)

// HardwareObservationAudit is an offline explanation of one saved observation.
// It does not resolve an IP, write facts, or assert a deployed result.
type HardwareObservationAudit struct {
	PayloadFields     []string                   `json:"payload_fields"`
	RuleInputs        []StoredHardwareSignal     `json:"rule_inputs"`
	OwnershipAccepted bool                       `json:"ownership_accepted"`
	ActivityCurrent   bool                       `json:"activity_current"`
	Stage             string                     `json:"stage"`
	Reasons           []string                   `json:"reasons"`
	Result            fingerprint.HardwareResult `json:"hardware_replay"`
	// FieldReplay tests the library independently of physical attribution. It
	// must never be written as a device conclusion or counted as confirmed.
	FieldReplay     fingerprint.HardwareResult `json:"field_only_replay_not_device_conclusion"`
	ReferenceIssues []string                   `json:"reference_issues,omitempty"`
	RawRef          map[string]any             `json:"raw_ref,omitempty"`
}

func AuditHardwareObservation(o Observation, at time.Time) (HardwareObservationAudit, error) {
	a := HardwareObservationAudit{Stage: "rule_matching", Reasons: []string{}, RawRef: o.Evidence.RawRef, ActivityCurrent: o.ValidUntil.After(at) && !o.Withdrawn}
	if len(o.Evidence.RawRef) == 0 {
		a.ReferenceIssues = append(a.ReferenceIssues, "raw_reference_missing")
	} else if o.Evidence.RawRef["line_offset"] != nil && o.Evidence.RawRef["file_id"] == nil && o.Evidence.RawRef["content_sha256"] == nil {
		a.ReferenceIssues = append(a.ReferenceIssues, "relative_line_requires_source_batch_reference")
	}
	if o.Origin == "sip" && o.EventID == "zeek-e3b0c44298fc1c149afbf4c8" {
		a.ReferenceIssues = append(a.ReferenceIssues, "non_unique_legacy_sip_empty_content_digest")
	}
	for k := range o.Evidence.Payload {
		a.PayloadFields = append(a.PayloadFields, k)
	}
	sort.Strings(a.PayloadFields)
	var err error
	a.RuleInputs, err = hardwareObservationSignals(o)
	if err != nil {
		return a, err
	}
	fact, err := HardwareFactFromObservation(o)
	if err != nil {
		return a, err
	}
	a.OwnershipAccepted = fact != nil
	if fact == nil {
		a.Stage = "device_attribution"
		mac, e := net.ParseMAC(o.MAC)
		if e != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
			a.Reasons = append(a.Reasons, "missing_valid_device_mac")
		}
		if o.Node == "" || o.Site == "" || o.Domain == "" {
			a.Reasons = append(a.Reasons, "incomplete_capture_scope")
		}
		if o.Origin == "sip" && o.EventID == "zeek-e3b0c44298fc1c149afbf4c8" {
			a.Reasons = append(a.Reasons, "non_unique_source_reference_requires_original_replay")
		}
		if !hardwareDirectOwnership(o) {
			a.Reasons = append(a.Reasons, "device_side_ownership_not_proven")
		}
		if len(a.Reasons) == 0 {
			a.Reasons = append(a.Reasons, "protocol_response_admission_not_satisfied")
		}
	}
	if len(a.RuleInputs) == 0 {
		a.Reasons = append(a.Reasons, "no_supported_hardware_fields")
		if fact != nil {
			a.Stage = "feature_extraction"
		}
	}
	if o.Withdrawn {
		a.Stage = "evidence_validity"
		a.Reasons = append(a.Reasons, "withdrawn")
	}
	if o.ObservedAt.After(at) {
		a.Stage = "evidence_validity"
		a.Reasons = append(a.Reasons, "future_observation")
	}
	if !a.ActivityCurrent {
		a.Reasons = append(a.Reasons, "activity_window_expired_or_withdrawn")
	}
	evidence := (HardwareFact{Signals: a.RuleInputs, EvidenceID: o.EventID, ObservedAt: o.ObservedAt, Revoked: o.Withdrawn}).Evidence()
	a.FieldReplay = fingerprint.EvaluateHardware(fingerprint.HardwareInput{IdentityTrusted: true, Evidence: evidence}, at)
	a.Result = fingerprint.EvaluateHardware(fingerprint.HardwareInput{IdentityTrusted: fact != nil, Evidence: evidence}, at)
	if fact == nil && a.FieldReplay.Type != "" {
		a.Reasons = append(a.Reasons, "product_fields_match_but_hardware_ownership_not_proven")
	} else if len(a.RuleInputs) > 0 && a.FieldReplay.Type == "" && !a.FieldReplay.Incomplete && !o.Withdrawn && !o.ObservedAt.After(at) {
		a.Reasons = append(a.Reasons, "no_type_match_for_available_fields")
	}
	if a.Result.Incomplete {
		a.Stage = "rule_runtime"
		a.Reasons = append(a.Reasons, a.Result.Error)
	} else if a.Result.TypeStatus == "conflict" {
		a.Stage = "evidence_conflict"
	} else if a.Result.Type != "" {
		a.Stage = "type_supported"
	} else if fact != nil && len(a.RuleInputs) > 0 {
		a.Reasons = append(a.Reasons, "no_type_rule_match")
	}
	return a, nil
}
