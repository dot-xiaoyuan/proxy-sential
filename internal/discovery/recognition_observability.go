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
	if len(f.Protocol) > 64 || len(f.MAC)+len(f.IP)+len(f.Sensor)+len(f.Site)+len(f.EvidenceEvent) > 2048 {
		input.Protocol = strings.TrimSpace(item.Protocol)
		return input, "diagnostic_limit"
	}
	input.MAC, input.IP, input.Sensor, input.Site, input.Observed, input.ValidUntil = f.MAC, f.IP, f.Sensor, f.Site, f.Observed, f.ValidUntil
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

// Resolve each distinct association context once in the receipt INSERT. There
// are no per-event round trips or second receipt UPDATEs on the ingestion path.
const insertRecognitionReceiptsSQL = `WITH inputs AS MATERIALIZED (
 SELECT * FROM jsonb_to_recordset($3::jsonb) AS v(scope_id text,event_key text,content_sha256 text,accepted_at timestamptz,result text,body_ref jsonb,recognition_input jsonb,recognition_status text)
), fresh AS MATERIALIZED (
 SELECT * FROM inputs WHERE accepted_at >=
  (SELECT (state->>'since')::timestamptz FROM read_model_runtime_state WHERE name='recognition-fresh-cutoff')
), contexts AS MATERIALIZED (
 SELECT DISTINCT recognition_input FROM fresh WHERE recognition_status='unattributed'
), resolved AS MATERIALIZED (
 SELECT v.recognition_input,ownership.targets FROM contexts v ` + recognitiondiag.TargetsLateralSQL + `
), monitored AS (
 SELECT f.scope_id,f.event_key,f.recognition_input||jsonb_build_object('targets',COALESCE(r.targets,'[]'::jsonb)) AS input,
 CASE WHEN f.recognition_status='unattributed' AND jsonb_array_length(COALESCE(r.targets,'[]'::jsonb))=1 THEN 'processing' ELSE f.recognition_status END AS status
 FROM fresh f LEFT JOIN resolved r ON r.recognition_input=f.recognition_input
)
INSERT INTO stream_discovery_receipts(accepted_month,epoch,scope_id,event_key,content_sha256,accepted_at,result,body_ref,recognition_input,recognition_status,recognition_check_after)
SELECT $1,$2,v.scope_id,v.event_key,v.content_sha256,v.accepted_at,v.result,v.body_ref,m.input,COALESCE(m.status,''),
 CASE WHEN m.status IN ('processing','unattributed') THEN clock_timestamp() ELSE NULL END
FROM inputs v LEFT JOIN monitored m USING(scope_id,event_key)
ON CONFLICT DO NOTHING`
