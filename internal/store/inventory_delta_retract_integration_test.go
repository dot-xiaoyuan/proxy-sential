package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Migration 122 dropped the old-endpoint branch of record_inventory_projection_delta, so
// a source row that moved to another endpoint left the old endpoint's contributions in
// place forever. The old endpoint must receive a retraction delta carrying the same
// origin key so its projection re-reads the source and drops the stale contribution.
func TestInventoryDeltaRetractsOldEndpointOnReassignment(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	event, oldEndpoint, newEndpoint := "retract-"+suffix, "mac:old-"+suffix, "mac:new-"+suffix
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pg.db.ExecContext(ctx, `INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen) VALUES($1,$2,'acct','192.0.2.9','replay',$3,$3)`, event, oldEndpoint, at); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.db.ExecContext(ctx, `UPDATE identity_ip_mac_history SET endpoint_id=$2 WHERE event_id=$1`, event, newEndpoint); err != nil {
		t.Fatal(err)
	}
	var operation, source, payloadEvent string
	err := pg.db.QueryRowContext(ctx, `SELECT operation,payload->>'source',payload->>'event_id' FROM endpoint_inventory_projection_deltas WHERE endpoint_id=$1 AND source_table='identity_ip_mac_history' ORDER BY delta_id DESC LIMIT 1`, oldEndpoint).Scan(&operation, &source, &payloadEvent)
	if err != nil {
		t.Fatalf("old endpoint received no retraction delta: %v", err)
	}
	if operation != "D" || source != "replay" || payloadEvent != event {
		t.Fatalf("retraction delta lacks the origin key: op=%s source=%s event=%s", operation, source, payloadEvent)
	}
	var updates int
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_inventory_projection_deltas WHERE endpoint_id=$1 AND operation='U'`, newEndpoint).Scan(&updates); err != nil || updates != 1 {
		t.Fatalf("new endpoint delta missing: %d %v", updates, err)
	}
}
