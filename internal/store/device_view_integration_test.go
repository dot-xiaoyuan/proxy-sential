package store

import (
	"context"
	"os"
	"proxy-sentinel/internal/normalized"
	"reflect"
	"testing"
	"time"
)

func TestDeviceViewPostgresReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	macs := []string{"00:10:20:30:40:61", "00:10:20:30:40:62", "00:10:20:30:40:63"}
	for i, mac := range macs {
		at := now.Add(-time.Hour)
		if i == 1 {
			at = now.Add(-48 * time.Hour)
		}
		if i == 2 {
			at = now.Add(time.Hour)
		}
		e := leaseEvent("view-"+mac, mac, at.Format(time.RFC3339Nano), "ACK")
		if err = s.WriteIdentityEvents(ctx, []normalized.Event{e}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListEndpointDevices(ctx, Query{View: "recent", Window: "24h", Q: "192.0.2.192", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page.Page.Total != 1 || len(page.Items) != 1 || page.Items[0].IPMatch == nil || page.Items[0].PrimaryMAC != macs[0] {
		t.Fatalf("recent %+v", page)
	}
	history, err := s.ListEndpointDevices(ctx, Query{Q: "192.0.2.192", Limit: 1})
	if err != nil || history.Page.Total != 3 || history.Page.NextCursor == nil {
		t.Fatalf("legacy history %+v %v", history, err)
	}
	// Fresh endpoint with only old IP observations must not match the recent IP window.
	if _, err = s.db.ExecContext(ctx, `UPDATE endpoint_entities SET last_seen=now() WHERE endpoint_id=$1`, "mac:"+macs[1]); err != nil {
		t.Fatal(err)
	}
	page, err = s.ListEndpointDevices(ctx, Query{View: "recent", Window: "24h", Q: "192.0.2.192", Limit: 20})
	if err != nil || page.Page.Total != 1 {
		t.Fatalf("old IP leaked %+v %v", page, err)
	}
	// A session starting before the window and ending inside it is a valid match.
	if _, err = s.db.ExecContext(ctx, `INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,source,started_at,ended_at,identity_confidence,raw_ref) VALUES('view-session','view-account',$1,'192.0.2.192','test',$2,$3,0.9,'{}')`, "mac:"+macs[1], now.Add(-48*time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	page, err = s.ListEndpointDevices(ctx, Query{View: "recent", Window: "24h", Q: "192.0.2.192", Limit: 20})
	if err != nil || page.Page.Total != 2 {
		t.Fatalf("session missed %+v %v", page, err)
	}
	for _, d := range page.Items {
		if d.PrimaryMAC == macs[1] && (d.IPMatch == nil || d.IPMatch.Source != "account_session") {
			t.Fatalf("wrong match %+v", d.IPMatch)
		}
	}
	// Latest endpoint IP may differ; annotation must retain the searched historical address.
	next := leaseEvent("view-move", macs[0], now.Add(-time.Minute).Format(time.RFC3339Nano), "ACK")
	next.Subject["ip"] = "192.0.2.200"
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{next}); err != nil {
		t.Fatal(err)
	}
	moved, err := s.ListEndpointDevices(ctx, Query{View: "recent", Window: "24h", Q: "192.0.2.192", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range moved.Items {
		if d.PrimaryMAC == macs[0] && (d.IPMatch == nil || d.IPMatch.IsRecentIP || d.IPMatch.IP != "192.0.2.192") {
			t.Fatalf("historical annotation %+v", d)
		}
	}
	recentFacets, err := s.ListEndpointDevices(ctx, Query{View: "recent", Window: "24h", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	otherFacets, err := s.ListEndpointDevices(ctx, Query{View: "recent", Window: "24h", Limit: 1, Cursor: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recentFacets.Facets, otherFacets.Facets) {
		t.Fatal("facets changed with page")
	}
	page, err = s.ListEndpointDevices(ctx, Query{View: "recent", Window: "24h", Q: "192.0.2.19", Limit: 20})
	if err != nil || page.Page.Total != 0 {
		t.Fatal("substring matched", err)
	}
}
