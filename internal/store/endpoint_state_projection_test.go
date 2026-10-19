package store

import (
	"strings"
	"testing"
)

// A device that stayed online since before the event stream existed has no open account_sessions
// row; the complete snapshot is the only evidence (10.157.2.191 on 184). The terminal row must read
// open members of the snapshot projection whose scope snapshot is still current, timed by the
// effective confirmation, with the same three-interval freshness rule the router bindings use.
func TestEndpointStateReadsCurrentSnapshotMembers(t *testing.T) {
	for _, required := range []string{
		"FROM account_identity_session_projection p JOIN account_identity_projection_sources src USING(source,sensor_id,campus_id,access_domain)",
		"p.document->>'endpoint_id'=e.endpoint_id",
		"COALESCE(p.document->>'ended_at','')=''",
		projectionCurrentSQL,
		"'at'," + projectionConfirmedSQL,
	} {
		if !strings.Contains(endpointStateSQL, required) {
			t.Fatalf("endpoint state SQL lacks %q", required)
		}
	}
	if !strings.Contains(projectionCurrentSQL, "src.observed_at>=now()-make_interval(secs=>GREATEST(60,LEAST(86400,COALESCE(NULLIF(p.document->>'reconcile_interval_seconds','')::int,1800)))*3)") {
		t.Fatalf("projection freshness differs from the router binding rule: %s", projectionCurrentSQL)
	}
}

// Projection membership changes (a member joins, changes or ends) must reach the terminal row through
// the change pass, not only through the 20-minute sweep.
func TestEndpointStateWatchesProjectionChanges(t *testing.T) {
	for _, source := range endpointStateSources {
		if source.name != "projection" {
			continue
		}
		for _, required := range []string{"FROM account_identity_session_projection", "(confirmed_at,document->>'endpoint_id')>($1,$2)", "ORDER BY confirmed_at,document->>'endpoint_id'"} {
			if !strings.Contains(source.query, required) {
				t.Fatalf("projection source lacks %q: %s", required, source.query)
			}
		}
		return
	}
	t.Fatal("projection is not an endpoint state change source")
}
