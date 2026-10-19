package store

import (
	"strings"
	"testing"
)

// A complete snapshot rewrote every member row of the projection: confirmed_at always moved, so
// each row was rewritten across all of its confirmed_at indexes and fired the shared-profile trigger,
// about 37 thousand jobs per snapshot. Only members whose content changed may be written.
func TestProjectionUpsertSkipsUnchangedMembers(t *testing.T) {
	guard := projectionUpsertSQL[strings.Index(projectionUpsertSQL, "DO UPDATE"):]
	for _, required := range []string{
		"account_identity_session_projection.account_id IS DISTINCT FROM EXCLUDED.account_id",
		"(account_identity_session_projection.document" + projectionVolatileKeys + ") IS DISTINCT FROM (EXCLUDED.document" + projectionVolatileKeys + ")",
	} {
		if !strings.Contains(guard, required) {
			t.Fatalf("upsert guard lacks %q:\n%s", required, guard)
		}
	}
	for _, volatile := range []string{"last_confirmed_at", "raw_ref", "started_at"} {
		if !strings.Contains(projectionVolatileKeys, "'"+volatile+"'") {
			t.Fatalf("volatile key %s still compared", volatile)
		}
	}
}

// An open member is confirmed by the scope's latest projected snapshot, not by a per-row write.
// Readers use this effective time, which equals what the per-row rewrite used to store.
func TestProjectionEffectiveConfirmationMatchesOldPerRowValue(t *testing.T) {
	want := "CASE WHEN COALESCE(p.document->>'ended_at','')='' THEN GREATEST(p.confirmed_at,COALESCE(src.observed_at,p.confirmed_at)) ELSE p.confirmed_at END"
	if projectionConfirmedSQL != want {
		t.Fatalf("effective confirmation changed:\n%s", projectionConfirmedSQL)
	}
	for name, query := range map[string]string{"router bindings": currentAuthSessionsSQL, "shared profile account": latestSharedProfileAccountSQL, "account detail": projectedAccountSessionsSQL} {
		if !strings.Contains(query, projectionConfirmedSQL) {
			t.Fatalf("%s reader does not use the effective confirmation", name)
		}
		if !strings.Contains(query, "account_identity_projection_sources src") {
			t.Fatalf("%s reader does not join the scope's latest snapshot", name)
		}
	}
}
