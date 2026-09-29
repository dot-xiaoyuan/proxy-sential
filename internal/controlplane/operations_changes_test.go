package controlplane

import "testing"

func TestOperationChangesIncludeConnectorSecretAndNewHistory(t *testing.T) {
	doc := emptyOperationsDocument()
	doc.Connectors["c"] = ActionConnector{ConnectorID: "c", EncryptedSecret: "old"}
	doc.Cases["a"] = RiskCase{CaseID: "a"}
	s := &operationsState{doc: doc, recordBaseline: operationFingerprints(doc)}
	if s.operationChanged("case", "a", doc.Cases["a"]) {
		t.Fatal("unchanged case is dirty")
	}
	v := doc.Cases["a"]
	v.Comments = append(v.Comments, CaseComment{CommentID: "new"})
	if !s.operationChanged("case", "a", v) {
		t.Fatal("new history ignored")
	}
	c := doc.Connectors["c"]
	c.EncryptedSecret = "new"
	if !s.operationChanged("connector", "c", c) {
		t.Fatal("secret-only change ignored")
	}
	if s.operationChanged("setting", "global_stop", false) {
		t.Fatal("unchanged emergency stop is dirty")
	}
	if !s.operationChanged("case", "missing", RiskCase{}) {
		t.Fatal("new row ignored")
	}
}
