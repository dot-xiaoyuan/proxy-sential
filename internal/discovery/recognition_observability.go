package discovery

import (
	"strings"

	"proxy-sentinel/internal/recognitiondiag"
)

// Metadata stays outside streamDiscoveryReceipt because that type participates
// in the immutable segment hash. Retries must retain the original hash.
func recognitionInput(item streamPreparedDiscovery) (recognitiondiag.Input, string) {
	input := recognitiondiag.Input{Protocol: item.Protocol, Parsed: item.Parsed}
	if len(input.Protocol) > 64 {
		input.Protocol = "other"
		return input, "diagnostic_limit"
	}
	if !item.Parsed {
		return input, "parse_error"
	}
	if !item.HasFact {
		return input, "outside_scope"
	}
	f := item.Fact
	input.Protocol = f.Protocol
	input.Features = len(f.RecognitionFields)
	// Never truncate an association key into a different device identity. Keep
	// oversized metadata in the authoritative event and expose the diagnostic
	// gap explicitly. This also guarantees one row fits the observer byte budget.
	if len(f.Protocol) > 64 || len(f.MAC)+len(f.IP)+len(f.Sensor)+len(f.Site)+len(f.Domain)+len(f.VLAN)+len(f.VRF)+len(f.Interface)+len(f.EvidenceEvent) > 2048 {
		input.Protocol = strings.TrimSpace(item.Protocol)
		return input, "diagnostic_limit"
	}
	input.MAC, input.IP, input.Sensor, input.Site, input.Observed, input.ValidUntil = f.MAC, f.IP, f.Sensor, f.Site, f.Observed, f.ValidUntil
	input.Domain, input.VLAN, input.VRF, input.Interface, input.AddressBinding = f.Domain, f.VLAN, f.VRF, f.Interface, f.AddressBinding
	input.Withdrawn = f.Withdrawn
	input.EvidenceEvent = f.EvidenceEvent
	if item.Receipt.Result == "late_history" {
		return input, "superseded"
	}
	// A withdrawal can remove the last product field; still wait for the target
	// generation so disappearance is measured rather than called an empty input.
	if f.Withdrawn {
		return input, "unattributed"
	}
	if input.Features == 0 {
		return input, "no_features"
	}
	return input, "unattributed"
}

// The fact transaction only appends compact diagnostic input. Ownership and
// generation observation run in the separately bounded background observer.
// A cold association lookup must never roll back authoritative fresh input.
const insertRecognitionReceiptsSQL = `WITH inputs AS MATERIALIZED (
 SELECT * FROM jsonb_to_recordset($3::jsonb) AS v(scope_id text,event_key text,content_sha256 text,accepted_at timestamptz,result text,body_ref jsonb,recognition_input jsonb,recognition_status text)
), fresh AS MATERIALIZED (
 SELECT * FROM inputs WHERE accepted_at >=
  (SELECT (state->>'since')::timestamptz FROM read_model_runtime_state WHERE name='recognition-fresh-cutoff')
)
INSERT INTO stream_discovery_receipts(accepted_month,epoch,scope_id,event_key,content_sha256,accepted_at,result,body_ref,recognition_input,recognition_status,recognition_check_after)
SELECT $1,$2,v.scope_id,v.event_key,v.content_sha256,v.accepted_at,v.result,v.body_ref,m.recognition_input,COALESCE(m.recognition_status,''),
 CASE WHEN m.recognition_status IN ('processing','unattributed') THEN clock_timestamp() ELSE NULL END
FROM inputs v LEFT JOIN fresh m USING(scope_id,event_key)
ON CONFLICT DO NOTHING`
