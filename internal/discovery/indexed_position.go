package discovery

import (
	"context"
	"fmt"
	"time"

	"proxy-sentinel/internal/pagination"
)

// DevicesIndexedPosition locates a numbered page using only ordered identity
// keys from the same current index and filters as the list and metadata.
func (r Repository) DevicesIndexedPosition(ctx context.Context, q DeviceQuery, page int) (pagination.Position, error) {
	q.Cursor, q.Offset = "", 0
	selection, err := buildIndexedDeviceSelection(q)
	if err != nil {
		return pagination.Position{}, err
	}
	q = selection.Query
	offset, err := pagination.BoundaryOffset(page, q.Limit)
	result := pagination.Position{Page: page, Limit: q.Limit, AsOf: time.Now().UTC()}
	if err != nil || page == 1 {
		return result, err
	}
	args := append(selection.Args, offset)
	rows, err := r.DB.QueryContext(ctx, selection.CTE+` SELECT identity_key,device_key,last_seen FROM matched ORDER BY last_seen DESC,identity_key COLLATE "C" LIMIT 2 OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	var boundary DeviceView
	count := 0
	for rows.Next() {
		var item DeviceView
		if err = rows.Scan(&item.indexedIdentityKey, &item.ID, &item.LastSeen); err != nil {
			return result, err
		}
		if count == 0 {
			boundary = item
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if count != 2 {
		return result, pagination.ErrPageOutOfRange
	}
	result.Cursor, err = encodeIndexedDeviceCursor(q, boundary)
	return result, err
}
