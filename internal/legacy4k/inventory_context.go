package legacy4k

import "context"

func (in OnlineInventory) StatsContext(ctx context.Context) (InventoryStats, error) {
	return in.walkIdentityRows(ctx, nil)
}
