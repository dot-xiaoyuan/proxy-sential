package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"proxy-sentinel/internal/pagination"
)

type EndpointRegistrationPositionReader interface {
	EndpointRegistrationPosition(context.Context, EndpointRegistrationQuery, int) (pagination.Position, error)
}

func (s *PostgresStore) EndpointRegistrationPosition(ctx context.Context, query EndpointRegistrationQuery, page int) (pagination.Position, error) {
	query.Cursor = ""
	q, err := NormalizeEndpointRegistrationQuery(query)
	result := pagination.Position{Page: page, Limit: q.Limit, AsOf: time.Now().UTC()}
	if err != nil {
		return result, err
	}
	offset, err := pagination.BoundaryOffset(page, q.Limit)
	if err != nil || page == 1 {
		return result, err
	}
	where, args := registrationCatalogWhere(q)
	args = append(args, offset)
	rows, err := s.db.QueryContext(ctx, `SELECT endpoint_id FROM endpoint_entities WHERE `+where+` ORDER BY endpoint_id LIMIT 2 OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	var boundary string
	count := 0
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return result, err
		}
		if count == 0 {
			boundary = id
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if count != 2 {
		return result, pagination.ErrPageOutOfRange
	}
	result.Cursor = encodeRegistrationCursor(q, boundary)
	return result, nil
}

func (s *DBStore) EndpointRegistrationPosition(ctx context.Context, q EndpointRegistrationQuery, page int) (pagination.Position, error) {
	return s.pg.EndpointRegistrationPosition(ctx, q, page)
}

// inventoryPosition reuses the fully filtered lookup predicate. Only two sort
// keys are returned; it does not read list_item JSON, evidence, or metadata.
func inventoryPosition(ctx context.Context, conn *sql.Conn, q Query, whereSQL string, args []any, now time.Time, state InventoryProjectionState) (DeviceInventoryListPage, error) {
	result := DeviceInventoryListPage{Items: []DeviceInventoryListItem{}, Page: Page{Limit: q.Limit}, AsOf: now.Format(time.RFC3339Nano), ReadModelState: &state}
	offset, err := pagination.BoundaryOffset(q.InventoryPositionPage, q.Limit)
	if err != nil {
		return result, err
	}
	if q.InventoryPositionPage == 1 {
		cursor := ""
		result.Page.NextCursor = &cursor
		return result, nil
	}
	args = append(append([]any{}, args...), offset)
	rows, err := conn.QueryContext(ctx, `SELECT i.endpoint_id,i.last_seen`+whereSQL+` ORDER BY i.last_seen DESC NULLS LAST,i.endpoint_id LIMIT 2 OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	var id string
	var lastSeen sql.NullTime
	count := 0
	for rows.Next() {
		var nextID string
		var nextTime sql.NullTime
		if err = rows.Scan(&nextID, &nextTime); err != nil {
			return result, err
		}
		if count == 0 {
			id, lastSeen = nextID, nextTime
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if count != 2 {
		return result, pagination.ErrPageOutOfRange
	}
	var at *time.Time
	if lastSeen.Valid {
		at = &lastSeen.Time
	}
	cursor, err := encodeInventoryCursor(q, at, id)
	if err != nil {
		return result, err
	}
	result.Page.NextCursor = &cursor
	return result, nil
}
