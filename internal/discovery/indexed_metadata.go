package discovery

import (
	"context"
	"time"
)

type IndexedDeviceMetadata struct {
	Total     int64     `json:"total"`
	AsOf      time.Time `json:"as_of"`
	CountUnit string    `json:"count_unit"`
	Window    string    `json:"window"`
}

// DevicesIndexedMetadata counts the same filtered trusted-identity groups as
// DevicesIndexed, independently of cursor/limit. Only the count is returned to
// Go; errors remain errors and are never reported as an empty inventory.
func (r Repository) DevicesIndexedMetadata(ctx context.Context, q DeviceQuery) (IndexedDeviceMetadata, error) {
	q.Cursor = ""
	q.Offset = 0
	q.Limit = 50
	selection, err := buildIndexedDeviceSelection(q)
	if err != nil {
		return IndexedDeviceMetadata{}, err
	}
	result := IndexedDeviceMetadata{CountUnit: "trusted_discovery_identity", Window: indexedWindowLabel(selection.Query.Window)}
	err = r.DB.QueryRowContext(ctx, selection.CTE+` SELECT count(*),now() FROM matched`, selection.Args...).Scan(&result.Total, &result.AsOf)
	return result, err
}
