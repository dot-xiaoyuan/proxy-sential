package discovery

import (
	"context"
	"testing"
	"time"
)

func TestDiscoveryLatestWithdrawalLateAndFutureReplay(t *testing.T) {
	db := legacyDiscoveryReplayDB(t)
	r := Repository{DB: db}
	ctx := context.Background()
	now := time.Now().UTC()
	key := "latest-replay"
	insert := func(id string, at time.Time, withdraw bool) {
		_, e := db.Exec(`INSERT INTO discovery_observations VALUES($1,$2,'latest-replay','ssdp',$3,$4,$5,'{"origin":"ssdp"}')`, id, key, at, now.Add(time.Hour), withdraw)
		if e != nil {
			t.Fatal(e)
		}
	}
	insert("latest-active", now.Add(-time.Minute), false)
	insert("latest-future", now.Add(time.Hour), false)
	page, e := r.Devices(ctx, 20, 0)
	if e != nil || page["total"] != 1 {
		t.Fatalf("future hid current: %v %v", page, e)
	}
	insert("latest-withdraw", now.Add(-time.Second), true)
	insert("latest-late", now.Add(-30*time.Second), false)
	page, e = r.Devices(ctx, 20, 0)
	if e != nil || page["total"] != 0 {
		t.Fatalf("withdrawal resurrected: %v %v", page, e)
	}
}
