package store

import (
	"strings"
	"testing"
)

// A projection member records when the current continuous presence began, so policy reads can
// rebuild its confirmations from the snapshot log instead of every stored snapshot document.
func TestProjectionRecordsFirstConfirmation(t *testing.T) {
	insert := projectionUpsertSQL[:strings.Index(projectionUpsertSQL, "ON CONFLICT")]
	if !strings.Contains(insert, "rows.document::jsonb||jsonb_build_object('first_confirmed_at',$5::timestamptz)") {
		t.Fatalf("new members do not record their first confirmation:\n%s", insert)
	}
	update := projectionUpsertSQL[strings.Index(projectionUpsertSQL, "DO UPDATE"):]
	// A member that ended and reappears starts a new presence; an open member keeps its start, and a
	// row written before this field existed falls back to its stored confirmation, never earlier.
	want := "'{first_confirmed_at}',CASE WHEN COALESCE(account_identity_session_projection.document->>'ended_at','')<>'' THEN EXCLUDED.document->'first_confirmed_at' ELSE COALESCE(account_identity_session_projection.document->'first_confirmed_at',to_jsonb(account_identity_session_projection.confirmed_at)) END"
	if !strings.Contains(update, want) {
		t.Fatalf("update does not preserve or restart the first confirmation:\n%s", update)
	}
	// The value differs on every snapshot, so it must not make an unchanged member look changed.
	if !strings.Contains(projectionVolatileKeys, "'first_confirmed_at'") {
		t.Fatalf("first_confirmed_at is compared: %s", projectionVolatileKeys)
	}
}
