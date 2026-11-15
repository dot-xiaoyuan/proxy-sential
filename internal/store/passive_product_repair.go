package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proxy-sentinel/internal/discovery"
)

// applyIPProductRefresh updates a derived product annotation only. It cannot
// create a MAC, modify an address binding, or enqueue a physical hardware fact.
func applyIPProductRefresh(ctx context.Context, tx *sql.Tx, entry HardwareRepairEntry) (bool, string, error) {
	o := *entry.Observation
	clue, err := discovery.BuildIPProductClue(o, time.Now().UTC())
	if err != nil {
		return false, "", err
	}
	if clue == nil {
		return false, "not_verified_product_response", nil
	}
	if clue.RuleVersion != entry.ProductRefreshVersion {
		return false, "", fmt.Errorf("product rules changed since snapshot preparation")
	}
	key := entry.Key
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT data::text FROM discovery_observation_latest
 WHERE device_key=$1 AND source_id=$2 AND origin=$3 AND service_type=$4 AND port=$5 FOR UPDATE`, key[0], key[1], key[2], key[3], key[4]).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "source_changed", nil
	}
	if err != nil {
		return false, "", err
	}
	if repairHash(raw) != entry.SourceSHA256 {
		var current discovery.Observation
		if err = json.Unmarshal(raw, &current); err != nil {
			return false, "", err
		}
		if current.EventID == o.EventID && current.ProductClue != nil && current.ProductClue.SourceSHA256 == entry.SourceSHA256 && current.ProductClue.RuleVersion == entry.ProductRefreshVersion {
			return true, "already_product_refreshed", nil
		}
		return false, "source_changed", nil
	}
	clue.SourceSHA256 = entry.SourceSHA256
	data, err := json.Marshal(clue)
	if err != nil {
		return false, "", err
	}
	if len(raw)+len(data) > HardwareRepairMaxRowBytes {
		return false, "product_annotation_exceeds_row_bound", nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE discovery_observation_latest SET data=jsonb_set(data,'{product_clue}',$6::jsonb)
 WHERE device_key=$1 AND source_id=$2 AND origin=$3 AND service_type=$4 AND port=$5`, key[0], key[1], key[2], key[3], key[4], string(data))
	return err == nil, "product_refreshed", err
}
