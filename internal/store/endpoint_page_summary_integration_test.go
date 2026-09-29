package store

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestEndpointPageSummaryMatchesDetailInventory(t *testing.T) {
	d := appIntegrationDB(t)
	s := d.store.pg
	ctx := context.Background()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	id := fmt.Sprintf("page-summary-%d", time.Now().UnixNano())
	mac := "02:00:00:99:77:01"
	events := []normalized.Event{}
	for i, ip := range []string{"192.0.2.2", "192.0.2.10"} {
		e := identityStoreEvent(fmt.Sprintf("%s-%d", id, i), fmt.Sprintf("account-%d", i), ip, mac, fmt.Sprintf("access-%d", i), "endpoint", "", stamp)
		e.Subject["endpoint_id"] = id
		events = append(events, e)
	}
	t.Cleanup(func() {
		for _, table := range []string{"endpoint_domain_evidence_events", "account_sessions", "identity_ip_mac_history", "identity_access_history", "endpoint_device_profiles", "endpoint_entities"} {
			if _, err := s.db.ExecContext(ctx, "DELETE FROM "+table+" WHERE endpoint_id=$1", id); err != nil {
				t.Error(err)
			}
		}
	})
	if err := s.WriteIdentityEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	profile, ok, err := s.GetEndpointIdentity(ctx, id, Query{Limit: 200})
	if err != nil || !ok {
		t.Fatalf("detail: %v %v", ok, err)
	}
	want := BuildEndpointDeviceInventory(profile)
	page, err := s.ListEndpointDevices(ctx, Query{Q: id, Limit: 20})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page: %+v %v", page.Page, err)
	}
	got := page.Items[0]
	if got.CurrentIP != want.CurrentIP || got.CurrentAccount != want.CurrentAccount || got.FirstSeen != want.FirstSeen || got.LastSeen != want.LastSeen || !reflect.DeepEqual(got.Accounts, want.Accounts) || !reflect.DeepEqual(got.IPs, want.IPs) || !reflect.DeepEqual(got.AccessIDs, want.AccessIDs) {
		t.Fatalf("summary changed identity: got=%+v want=%+v", got, want)
	}
}
