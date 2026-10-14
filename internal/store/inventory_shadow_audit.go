package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

type InventoryShadowAudit struct {
	State       InventoryProjectionState    `json:"state"`
	Compared    int                         `json:"compared"`
	Changed     int                         `json:"changed"`
	Concurrent  int                         `json:"concurrent"`
	Differences []InventoryShadowDifference `json:"differences"`
}
type InventoryShadowDifference struct {
	EndpointHash string   `json:"endpoint_hash"`
	Fields       []string `json:"fields"`
}

// AuditDeviceInventory is a controlled shadow check. Each reference rebuild is
// endpoint scoped and rolled back; it never publishes rebuilt rows or progress.
func (s *DBStore) AuditDeviceInventory(ctx context.Context, limit int) (InventoryShadowAudit, error) {
	result := InventoryShadowAudit{Differences: []InventoryShadowDifference{}}
	var err error
	result.State, err = inventoryProjectionState(ctx, s.pg.db)
	if err != nil {
		return result, err
	}
	if limit < 1 || limit > 200 {
		return result, fmt.Errorf("audit limit must be between 1 and 200")
	}
	rows, err := s.pg.db.QueryContext(ctx, `SELECT j.endpoint_id FROM endpoint_inventory_projection_jobs j JOIN endpoint_inventory_lookup i USING(endpoint_id) WHERE j.contributions_ready AND j.processed_generation=j.dirty_generation AND j.last_error='' ORDER BY i.last_seen DESC NULLS LAST,j.endpoint_id LIMIT $1`, limit)
	if err != nil {
		return result, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return result, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	for _, id := range ids {
		tx, e := s.pg.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if e != nil {
			return result, e
		}
		var before, after []byte
		e = tx.QueryRowContext(ctx, `SELECT i.list_item FROM endpoint_inventory_lookup i JOIN endpoint_inventory_projection_jobs j USING(endpoint_id) WHERE i.endpoint_id=$1 AND j.processed_generation=j.dirty_generation`, id).Scan(&before)
		if e == sql.ErrNoRows {
			tx.Rollback()
			result.Concurrent++
			continue
		}
		if e == nil {
			e = s.pg.materializeInventoryTx(ctx, tx, id)
		}
		if e == nil {
			e = tx.QueryRowContext(ctx, `SELECT list_item FROM endpoint_inventory_lookup WHERE endpoint_id=$1`, id).Scan(&after)
		}
		tx.Rollback()
		if e != nil {
			return result, e
		}
		var a, b map[string]any
		if e = json.Unmarshal(before, &a); e != nil {
			return result, e
		}
		if e = json.Unmarshal(after, &b); e != nil {
			return result, e
		}
		fields := []string{}
		keys := map[string]bool{}
		for k := range a {
			keys[k] = true
		}
		for k := range b {
			keys[k] = true
		}
		for k := range keys {
			if !reflect.DeepEqual(a[k], b[k]) {
				fields = append(fields, k)
			}
		}
		result.Compared++
		if len(fields) > 0 {
			sort.Strings(fields)
			result.Changed++
			digest := sha256.Sum256([]byte(id))
			result.Differences = append(result.Differences, InventoryShadowDifference{EndpointHash: fmt.Sprintf("%x", digest[:8]), Fields: fields})
		}
	}
	return result, nil
}
