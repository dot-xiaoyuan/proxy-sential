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
	if entry.SourceRelation == "observation" {
		err = tx.QueryRowContext(ctx, `SELECT data::text FROM discovery_observations WHERE id=$1 FOR UPDATE`, entry.ObservationID).Scan(&raw)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT data::text FROM discovery_observation_latest
 WHERE device_key=$1 AND source_id=$2 AND origin=$3 AND service_type=$4 AND port=$5 FOR UPDATE`, key[0], key[1], key[2], key[3], key[4]).Scan(&raw)
	}
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
		if current.EventID == o.EventID && current.ProductClue != nil && current.ProductClue.SourceSHA256 == entry.SourceSHA256 && current.ProductClue.RuleVersion == entry.ProductRefreshVersion && (entry.SourceRelation != "observation" || current.LatestPartition == entry.Key[3]) {
			current.ProductClue, current.LatestPartition = o.ProductClue, o.LatestPartition
			original, marshalErr := json.Marshal(current)
			if marshalErr == nil && repairHash(original) == entry.InputSHA256 {
				return true, "already_product_refreshed", nil
			}
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
	if entry.SourceRelation == "observation" {
		partition := discovery.SNMPProductPartition(o)
		if partition == "" || partition != entry.Key[3] {
			return false, "", fmt.Errorf("product partition does not match frozen source")
		}
		_, err = tx.ExecContext(ctx, `UPDATE discovery_observations SET data=jsonb_set(jsonb_set(data,'{product_clue}',$2::jsonb),'{latest_partition}',to_jsonb($3::text)) WHERE id=$1`, entry.ObservationID, string(data), partition)
		return err == nil, "retained_product_projected", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE discovery_observation_latest SET data=jsonb_set(data,'{product_clue}',$6::jsonb)
 WHERE device_key=$1 AND source_id=$2 AND origin=$3 AND service_type=$4 AND port=$5`, key[0], key[1], key[2], key[3], key[4], string(data))
	return err == nil, "product_refreshed", err
}
