package discovery

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/pagination"
)

type HistoryMetadata struct {
	pagination.Metadata
	Snapshot time.Time `json:"snapshot"`
}
type HistoryPosition struct {
	pagination.Position
	Snapshot time.Time `json:"snapshot"`
}

func (r Repository) discoveryHistoryEpoch(ctx context.Context, key string) (string, error) {
	var epoch string
	err := r.DB.QueryRowContext(ctx, `SELECT s.epoch FROM stream_discovery_device_state s
 WHERE s.device_key=$1 AND EXISTS(SELECT 1 FROM stream_source_cutovers c WHERE c.epoch=s.epoch AND c.state='active')
 ORDER BY s.last_seen DESC LIMIT 1`, key).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return epoch, err
}

func validHistoryDevice(key string) error {
	if strings.TrimSpace(key) == "" || len(key) > 1024 {
		return fmt.Errorf("invalid history device_id")
	}
	return nil
}
func historySelection(epoch, key string, snapshot time.Time) (string, string, []any) {
	if epoch != "" {
		return "stream_discovery_changes", "epoch=$1 AND device_key=$2 AND accepted_at<=$3", []any{epoch, key, snapshot}
	}
	return "discovery_device_changes_v2", "device_key=$1 AND ingested_at<=$2", []any{key, snapshot}
}

// DiscoveryHistoryMetadata counts only this device's existing change index. It
// never loads historical documents or reconstructs current device state.
func (r Repository) DiscoveryHistoryMetadata(ctx context.Context, key string, snapshot time.Time) (HistoryMetadata, error) {
	if snapshot.IsZero() {
		snapshot = time.Now().UTC()
	}
	result := HistoryMetadata{Metadata: pagination.Metadata{AsOf: snapshot}, Snapshot: snapshot}
	if err := validHistoryDevice(key); err != nil {
		return result, err
	}
	epoch, err := r.discoveryHistoryEpoch(ctx, key)
	if err != nil {
		return result, err
	}
	table, where, args := historySelection(epoch, key, snapshot)
	err = r.DB.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE `+where, args...).Scan(&result.Total)
	return result, err
}

// DiscoveryHistoryPosition reads at most the preceding and first target keys.
// The list retains its existing versioned device/epoch cursor and validates
// evidence receipts only for the page being read.
func (r Repository) DiscoveryHistoryPosition(ctx context.Context, key string, snapshot time.Time, page, limit int) (HistoryPosition, error) {
	if snapshot.IsZero() {
		snapshot = time.Now().UTC()
	}
	result := HistoryPosition{Position: pagination.Position{Page: page, Limit: limit, AsOf: snapshot}, Snapshot: snapshot}
	if err := validHistoryDevice(key); err != nil {
		return result, err
	}
	if limit > 100 {
		return result, fmt.Errorf("history limit must be between 1 and 100")
	}
	offset, err := pagination.BoundaryOffset(page, limit)
	if err != nil || page == 1 {
		return result, err
	}
	epoch, err := r.discoveryHistoryEpoch(ctx, key)
	if err != nil {
		return result, err
	}
	table, where, args := historySelection(epoch, key, snapshot)
	args = append(args, offset)
	rows, err := r.DB.QueryContext(ctx, `SELECT change_id FROM `+table+` WHERE `+where+fmt.Sprintf(" ORDER BY change_id DESC LIMIT 2 OFFSET $%d", len(args)), args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	count := 0
	var boundary int64
	for rows.Next() {
		var id int64
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
	version := 2
	if epoch != "" {
		version = 3
	}
	var raw []byte
	if epoch == "" {
		raw, err = json.Marshal(map[string]any{"k": key, "a": boundary, "v": version})
	} else {
		raw, err = json.Marshal(streamHistoryCursor{Key: key, Epoch: epoch, After: boundary, Version: version})
	}
	if err == nil {
		result.Cursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return result, err
}
