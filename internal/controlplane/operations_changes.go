package controlplane

import (
	"crypto/sha256"
	"encoding/json"
)

// Fingerprints are immutable snapshots, including fields not serialized to the
// API. Unchanged rows must not be resent by unrelated operations or workers.
func operationFingerprint(kind string, value any) [32]byte {
	if kind == "connector" {
		v := value.(ActionConnector)
		value = struct {
			Value  ActionConnector
			Secret string
		}{v, v.EncryptedSecret}
	}
	raw, _ := json.Marshal(value)
	return sha256.Sum256(raw)
}
func operationFingerprints(doc operationsDocument) map[[2]string][32]byte {
	out := map[[2]string][32]byte{}
	add := func(kind, id string, value any) { out[[2]string{kind, id}] = operationFingerprint(kind, value) }
	for id, v := range doc.Cases {
		add("case", id, v)
	}
	for id, v := range doc.Connectors {
		add("connector", id, v)
	}
	for id, v := range doc.Actions {
		add("action", id, v)
	}
	for id, v := range doc.Policies {
		add("policy", id, v)
	}
	for id, v := range doc.PolicyExecutions {
		add("execution", id, v)
	}
	add("setting", "global_stop", doc.GlobalStop)
	return out
}
func (s *operationsState) operationChanged(kind, id string, value any) bool {
	old, ok := s.recordBaseline[[2]string{kind, id}]
	return !ok || old != operationFingerprint(kind, value)
}
func (s *operationsState) changedPolicies() operationsDocument {
	out := emptyOperationsDocument()
	for id, v := range s.doc.Policies {
		if s.operationChanged("policy", id, v) {
			out.Policies[id] = v
		}
	}
	for id, v := range s.doc.PolicyExecutions {
		if s.operationChanged("execution", id, v) {
			out.PolicyExecutions[id] = v
		}
	}
	return out
}

func operationRecordVersions(doc operationsDocument) map[[2]string]string {
	versions := map[[2]string]string{}
	for id, v := range doc.Connectors {
		versions[[2]string{"connector", id}] = v.UpdatedAt
	}
	for id, v := range doc.Actions {
		versions[[2]string{"action", id}] = v.UpdatedAt
	}
	return versions
}
