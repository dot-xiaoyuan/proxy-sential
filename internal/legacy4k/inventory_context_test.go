package legacy4k

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"
)

type inventoryBoundaryCancel struct {
	context.Context
	cancel        context.CancelFunc
	checks, limit int
}

func (c *inventoryBoundaryCancel) Err() error {
	c.checks++
	if c.checks >= c.limit {
		c.cancel()
	}
	return c.Context.Err()
}
func TestInventoryContextCancellationDropsPartialRecordsAndStats(t *testing.T) {
	for _, limit := range []int{1, 10, 65, 90, 125} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			in := memoryInventory(64)
			before, _ := json.Marshal(in)
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &inventoryBoundaryCancel{Context: parent, cancel: cancel, limit: limit}
			records, stats, err := in.IdentityRecordsWithStatsContext(ctx)
			if records != nil || stats != (InventoryStats{}) || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled inventory returned records=%d stats=%+v checks=%d err=%v", len(records), stats, ctx.checks, err)
			}
			if ctx.checks > limit+1 {
				t.Fatal("expansion continued after cancellation")
			}
			after, _ := json.Marshal(in)
			if !bytes.Equal(before, after) {
				t.Fatal("source rows mutated")
			}
		})
	}
}
func TestInventoryStatsContextDeadlineRetainsCause(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	stats, err := memoryInventory(2).StatsContext(ctx)
	if stats != (InventoryStats{}) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired count returned %+v %v", stats, err)
	}
}

func TestInventoryContextNativeMaximum(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_IDENTITY_LOCAL_MAXIMUM") != "1" {
		t.Skip("explicit isolated maximum identity acceptance required")
	}
	in := memoryInventory(100000)
	records, stats, err := in.IdentityRecordsWithStatsContext(context.Background())
	if err != nil || len(records) != 200000 || stats.Sessions != 100000 || stats.AddressRecords != 200000 || stats.Accounts != 1 {
		t.Fatalf("maximum expansion records=%d stats=%+v err=%v", len(records), stats, err)
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &inventoryBoundaryCancel{Context: parent, cancel: cancel, limit: 100512}
	partial, coverage, err := in.IdentityRecordsWithStatsContext(ctx)
	if partial != nil || coverage != (InventoryStats{}) || !errors.Is(err, context.Canceled) || ctx.checks > 100513 {
		t.Fatal("maximum expansion interruption published partial coverage")
	}
	t.Log("100000 dual-stack sessions expanded to 200000 records; interruption during expansion returned nil records and zero coverage")
}
