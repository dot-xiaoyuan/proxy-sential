package store

import (
	"encoding/json"
	"strings"
	"testing"

	"proxy-sentinel/internal/evidence"
)

func TestPrepareRouterEvidenceBatchUsesStableKeyOrder(t *testing.T) {
	z := evidence.RouterEvidence{EvidenceID: "z", AssessmentID: "router-z", IP: "192.0.2.2", LastSeen: "2026-11-11T00:01:00Z", ExpiresAt: "2026-11-11T00:30:00Z"}
	a := evidence.RouterEvidence{EvidenceID: "a", AssessmentID: "router-a", SourceFamily: "shared_gateway_behavior", LastSeen: "2026-11-11T00:02:00Z", ExpiresAt: "2026-11-11T00:10:00Z"}
	rows, repeated, err := prepareRouterEvidenceBatch([]evidence.RouterEvidence{z, a})
	if err != nil || repeated || len(rows) != 2 || rows[0].EvidenceID != "a" || rows[1].EvidenceID != "z" {
		t.Fatalf("unexpected batch: rows=%+v repeated=%t err=%v", rows, repeated, err)
	}
	var decoded evidence.RouterEvidence
	if err := json.Unmarshal(rows[0].Data, &decoded); err != nil || decoded.SourceFamily != a.SourceFamily || decoded.ExpiresAt != a.ExpiresAt {
		t.Fatalf("evidence document changed: %+v %v", decoded, err)
	}
	if !strings.Contains(insertRouterEvidenceBatchSQL, "ORDER BY evidence_id") || !strings.Contains(insertRouterEvidenceBatchSQL, "GREATEST(router_evidence_facts.expires_at,EXCLUDED.expires_at)") {
		t.Fatal("batch SQL must keep lock order and prior expiry semantics")
	}
}

func TestPrepareRouterEvidenceBatchFallsBackForRepeatedKey(t *testing.T) {
	old := evidence.RouterEvidence{EvidenceID: "same", LastSeen: "2026-11-11T00:01:00Z", ExpiresAt: "2026-11-11T00:30:00Z"}
	newer := old
	newer.LastSeen = "2026-11-11T00:02:00Z"
	newer.ExpiresAt = "2026-11-11T00:10:00Z"
	rows, repeated, err := prepareRouterEvidenceBatch([]evidence.RouterEvidence{old, newer})
	if err != nil || !repeated || len(rows) != 0 {
		t.Fatalf("repeated evidence must retain ordered single-row writes: rows=%+v repeated=%t err=%v", rows, repeated, err)
	}
	if !strings.Contains(insertRouterEvidenceSingleSQL, "EXCLUDED.last_seen>=router_evidence_facts.last_seen") {
		t.Fatal("fallback must preserve persisted-row conflict condition")
	}
}
