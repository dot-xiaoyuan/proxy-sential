package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// Seed a bounded page of existing current summaries, without reading history.
// These rows are explicitly incomplete until contribution backfill catches up.
// Concurrent fully prepared rows always win over bootstrap summaries.
func (s *PostgresStore) bootstrapInventorySummaries(ctx context.Context, limit int) error {
	if limit < 1 || limit > 2000 {
		limit = 2000
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cursor string
	var done bool
	if err = tx.QueryRowContext(ctx, `SELECT summary_cursor,summary_complete FROM endpoint_inventory_projection_state WHERE singleton`).Scan(&cursor, &done); err != nil {
		return err
	}
	if done {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.endpoint_id,coalesce(r.list_item,'{}'),coalesce(e.primary_mac,''),coalesce(nullif(n.value,''),r.device_name,''),e.last_seen,coalesce(e.owner_account,''),coalesce(e.owner_name,''),coalesce(n.value,'')<>'' FROM endpoint_entities e LEFT JOIN endpoint_recognition_summary r USING(endpoint_id) LEFT JOIN device_name_notes n USING(endpoint_id) WHERE e.endpoint_id>$1 ORDER BY e.endpoint_id LIMIT $2`, cursor, limit)
	if err != nil {
		return err
	}
	type seed struct {
		id, mac, name, ownerAccount, ownerName string
		raw                                    []byte
		seen                                   sql.NullTime
		manual                                 bool
	}
	seeds := []seed{}
	for rows.Next() {
		var v seed
		if err = rows.Scan(&v.id, &v.raw, &v.mac, &v.name, &v.seen, &v.ownerAccount, &v.ownerName, &v.manual); err != nil {
			rows.Close()
			return err
		}
		seeds = append(seeds, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range seeds {
		var item EndpointDeviceInventory
		if err = json.Unmarshal(v.raw, &item); err != nil {
			return err
		}
		item.EndpointID, item.PrimaryMAC, item.OwnerAccount, item.OwnerName = v.id, v.mac, v.ownerAccount, v.ownerName
		if v.seen.Valid && v.seen.Time.After(time.Now()) {
			v.seen = sql.NullTime{}
		}
		if v.seen.Valid {
			item.LastSeen = v.seen.Time.UTC().Format(time.RFC3339Nano)
		} else {
			item.LastSeen = ""
		}
		if v.name == "" {
			item.DeviceName = nil
		} else {
			if item.DeviceName == nil {
				item.DeviceName = &DeviceName{}
			}
			item.DeviceName.Value = v.name
			if v.manual {
				item.DeviceName.Manual = true
				item.DeviceName.Source = "manual_note"
				item.DeviceName.Status = "current"
			}
		}
		raw, e := json.Marshal(ProjectDeviceInventoryListItem(item))
		if e != nil {
			return e
		}
		mac := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(v.mac))
		search := strings.ToLower(strings.Join([]string{v.id, v.mac, mac, v.name, item.CurrentIP, item.CurrentAccount, item.CurrentAccessID, v.ownerAccount, v.ownerName, item.Brand, item.Model, item.OSFamily, item.DeviceType}, " "))
		result, err := tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_lookup(endpoint_id,list_item,last_seen,device_name,mac_key,current_ip,search_text) VALUES($1,$2,$3,$4,$5,nullif($6,'')::inet,$7) ON CONFLICT(endpoint_id) DO NOTHING`, v.id, raw, v.seen, v.name, mac, item.CurrentIP, search)
		if err != nil {
			return err
		}
		if inserted, _ := result.RowsAffected(); inserted > 0 {
			at, e := time.Parse(time.RFC3339Nano, item.CurrentAccountObservedAt)
			if e != nil {
				at = time.Unix(0, 0).UTC()
				if v.seen.Valid {
					at = v.seen.Time
				}
			}
			accounts := append([]string{}, item.CurrentAccountCandidates...)
			if len(accounts) == 0 && item.CurrentAccount != "" {
				accounts = append(accounts, item.CurrentAccount)
			}
			for _, account := range accounts {
				if _, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_accounts(endpoint_id,account_id,observed_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, v.id, account, at); err != nil {
					return err
				}
			}
		}
		cursor = v.id
	}
	if _, err = tx.ExecContext(ctx, `UPDATE endpoint_inventory_projection_state SET summary_cursor=$1,summary_complete=$2 WHERE singleton`, cursor, len(seeds) < limit); err != nil {
		return err
	}
	return tx.Commit()
}
