package discovery

import (
	"context"
	"time"
)

type IndexedDeviceMetadata struct {
	Total      int64                    `json:"total"`
	Identified int64                    `json:"identified"`
	Candidate  int64                    `json:"candidate"`
	Conflict   int64                    `json:"conflict"`
	Expired    int64                    `json:"expired"`
	Types      []IndexedDeviceTypeCount `json:"types"`
	AsOf       time.Time                `json:"as_of"`
	CountUnit  string                   `json:"count_unit"`
	Window     string                   `json:"window"`
}

type IndexedDeviceTypeCount struct {
	DeviceType string `json:"device_type"`
	Count      int64  `json:"count"`
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
	result := IndexedDeviceMetadata{CountUnit: "trusted_discovery_identity", Window: indexedWindowLabel(selection.Query.Window), Types: []IndexedDeviceTypeCount{}, AsOf: time.Now().UTC()}
	rows, err := r.DB.QueryContext(ctx, selection.CTE+` SELECT classification_status,
 CASE WHEN classification_status='identified' THEN effective_types[1] ELSE '' END device_type,
 count(*),now() FROM matched GROUP BY classification_status,device_type ORDER BY classification_status,device_type`, selection.Args...)
	if err != nil {
		return IndexedDeviceMetadata{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var state, kind string
		var count int64
		var at time.Time
		if err := rows.Scan(&state, &kind, &count, &at); err != nil {
			return IndexedDeviceMetadata{}, err
		}
		result.Total += count
		result.AsOf = at
		switch state {
		case "identified":
			result.Identified += count
			result.Types = append(result.Types, IndexedDeviceTypeCount{DeviceType: kind, Count: count})
		case "candidate":
			result.Candidate += count
		case "conflict":
			result.Conflict += count
		case "expired":
			result.Expired += count
		}
	}
	if err := rows.Err(); err != nil {
		return IndexedDeviceMetadata{}, err
	}
	return result, nil
}
