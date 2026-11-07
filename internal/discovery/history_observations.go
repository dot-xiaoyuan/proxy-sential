package discovery

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"proxy-sentinel/internal/pagination"
)

// The deployment reads discovery through the indexed observation path, which
// never writes discovery_device_changes_v2. Serve the device history from the
// retained observations in that case: every observation row is already the
// evidence the detail view uses, and the 30-day retention bounds the read.
// Devices that do have change rows keep the existing change-index behaviour.
func (r Repository) historyUsesObservations(ctx context.Context, key string) (bool, error) {
	var hasChanges bool
	if err := r.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_device_changes_v2 WHERE device_key=$1)`, key).Scan(&hasChanges); err != nil {
		return false, err
	}
	return !hasChanges, nil
}

type observationHistoryCursor struct {
	Key      string    `json:"k"`
	Observed time.Time `json:"t"`
	ID       string    `json:"i"`
	Version  int       `json:"v"`
}

func decodeObservationHistoryCursor(key, cursor string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid history cursor")
	}
	var parsed observationHistoryCursor
	if err = json.Unmarshal(raw, &parsed); err != nil || parsed.Key != key || parsed.Version != 4 || parsed.Observed.IsZero() || parsed.ID == "" {
		return time.Time{}, "", fmt.Errorf("invalid history cursor")
	}
	return parsed.Observed.UTC(), parsed.ID, nil
}

func encodeObservationHistoryCursor(key string, observed time.Time, id string) (string, error) {
	raw, err := json.Marshal(observationHistoryCursor{Key: key, Observed: observed.UTC(), ID: id, Version: 4})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// observationHistoryID is only the stable display key of one row. The cursor
// uses the observation id itself; this numeric value must not paginate or join.
func observationHistoryID(id string) int64 {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(id))
	return int64(hash.Sum64() & 0x7fffffffffffffff)
}

func (r Repository) ObservationHistoryMetadata(ctx context.Context, key string, snapshot time.Time) (HistoryMetadata, error) {
	result := HistoryMetadata{Metadata: pagination.Metadata{AsOf: snapshot}, Snapshot: snapshot}
	err := r.DB.QueryRowContext(ctx, `SELECT count(*) FROM discovery_observations WHERE device_key=$1 AND observed_at<=$2`, key, snapshot).Scan(&result.Total)
	return result, err
}

func (r Repository) ObservationHistoryPosition(ctx context.Context, key string, snapshot time.Time, page, limit int) (HistoryPosition, error) {
	result := HistoryPosition{Position: pagination.Position{Page: page, Limit: limit, AsOf: snapshot}, Snapshot: snapshot}
	if page <= 1 {
		return result, nil
	}
	offset, err := pagination.BoundaryOffset(page, limit)
	if err != nil {
		return result, err
	}
	var observed time.Time
	var id string
	err = r.DB.QueryRowContext(ctx, `
SELECT observed_at,id FROM discovery_observations
WHERE device_key=$1 AND observed_at<=$2
ORDER BY observed_at DESC,id DESC LIMIT 1 OFFSET $3`, key, snapshot, offset).Scan(&observed, &id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, pagination.ErrPageOutOfRange
		}
		return result, err
	}
	result.Cursor, err = encodeObservationHistoryCursor(key, observed, id)
	return result, err
}

type observationHistoryPageRow struct {
	item     map[string]any
	observed time.Time
	id       string
}

func (r Repository) ObservationHistoryAt(ctx context.Context, key, cursor string, limit int, snapshot time.Time) (map[string]any, error) {
	var afterObserved time.Time
	var afterID string
	if cursor != "" {
		observed, id, err := decodeObservationHistoryCursor(key, cursor)
		if err != nil {
			return nil, err
		}
		afterObserved, afterID = observed, id
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	args := []any{key, snapshot, limit + 1}
	where := "device_key=$1 AND observed_at<=$2"
	if !afterObserved.IsZero() {
		where += " AND (observed_at,id)<($4::timestamptz,$5::text)"
		args = append(args, afterObserved, afterID)
	}
	rows, err := r.DB.QueryContext(ctx, `
SELECT id,origin,observed_at,data FROM discovery_observations
WHERE `+where+`
ORDER BY observed_at DESC,id DESC LIMIT $3`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	built := []observationHistoryPageRow{}
	for rows.Next() {
		var id, origin string
		var observed time.Time
		var document json.RawMessage
		if err = rows.Scan(&id, &origin, &observed, &document); err != nil {
			return nil, err
		}
		var data map[string]any
		_ = json.Unmarshal(document, &data)
		eventID, _ := data["event_id"].(string)
		if eventID == "" {
			eventID = id
		}
		built = append(built, observationHistoryPageRow{
			observed: observed,
			id:       id,
			item: map[string]any{
				"id": observationHistoryID(id), "event_id": eventID,
				"ingested_at": observed, "observed_at": observed,
				"kind": origin, "evidence": document,
			},
		})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	more := len(built) > limit
	if more {
		built = built[:limit]
	}
	items := make([]map[string]any, 0, len(built))
	for _, row := range built {
		items = append(items, row.item)
	}
	next := ""
	if more && len(built) > 0 {
		last := built[len(built)-1]
		next, err = encodeObservationHistoryCursor(key, last.observed, last.id)
		if err != nil {
			return nil, err
		}
	}
	result := map[string]any{"items": items, "has_more": more, "next_cursor": next}
	if !snapshot.IsZero() {
		result["snapshot"] = snapshot
	}
	return result, nil
}
