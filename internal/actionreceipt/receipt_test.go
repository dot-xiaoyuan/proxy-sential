package actionreceipt

import "testing"

func TestCompletionContract(t *testing.T) {
	for _, raw := range []string{`{}`, `{"action_id":"r"}`, `{"code":0}`, `{"action_id":"r","status":"pending"}`, `{"action_id":"r","status":"failed"}`, `{"action_id":"r","status":"completed","success":false}`, `{"action_id":"r","status":"completed"}{}`, `<html>accepted</html>`} {
		if _, err := Completed([]byte(raw), false); err == nil {
			t.Fatal("noncompletion accepted", raw)
		}
	}
	for _, raw := range []string{`{"action_id":"r","status":"completed"}`, `{"action_id":"r","status":"succeeded"}`} {
		if id, err := Completed([]byte(raw), false); err != nil || id != "r" {
			t.Fatal(id, err)
		}
	}
	if _, err := Completed([]byte(`{"action_id":"r","status":"succeeded"}`), true); err == nil {
		t.Fatal("execution success treated as revocation")
	}
	if _, err := Completed([]byte(`{"action_id":"r","status":"revoked"}`), true); err != nil {
		t.Fatal(err)
	}
}
