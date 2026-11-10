package discovery

import (
	"context"
	"fmt"
	"time"
)

type DiscoveryTrendDay struct {
	Date  string `json:"date"`
	New   int    `json:"new"`
	Typed int    `json:"typed"`
}

type DiscoveryTrendType struct {
	DeviceType string `json:"device_type"`
	Count      int    `json:"count"`
}

type DiscoveryTrends struct {
	Days       []DiscoveryTrendDay  `json:"days"`
	TopTypes   []DiscoveryTrendType `json:"top_types,omitempty"`
	AsOf       time.Time            `json:"as_of"`
	WindowDays int                  `json:"window_days"`
}

// DiscoveryTrends counts newly seen endpoint profiles per UTC day. It reads
// the recognition summary only; no event or history scan.
func (r Repository) DiscoveryTrends(ctx context.Context, days int) (DiscoveryTrends, error) {
	if r.DB == nil {
		return DiscoveryTrends{}, fmt.Errorf("discovery trends need PostgreSQL")
	}
	if days < 1 || days > 30 {
		return DiscoveryTrends{}, fmt.Errorf("invalid trend window")
	}
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -days+1)
	rows, err := r.DB.QueryContext(ctx, `SELECT to_char(first_seen AT TIME ZONE 'UTC','YYYY-MM-DD'), count(*), count(*) FILTER (WHERE coalesce(role,'')<>'') FROM endpoint_recognition_summary WHERE first_seen>=$1 AND first_seen<=now() GROUP BY 1 ORDER BY 1`, start)
	if err != nil {
		return DiscoveryTrends{}, err
	}
	defer rows.Close()
	counts := map[string]DiscoveryTrendDay{}
	for rows.Next() {
		var day DiscoveryTrendDay
		if err = rows.Scan(&day.Date, &day.New, &day.Typed); err != nil {
			return DiscoveryTrends{}, err
		}
		counts[day.Date] = day
	}
	if err = rows.Err(); err != nil {
		return DiscoveryTrends{}, err
	}
	typeRows, err := r.DB.QueryContext(ctx, `SELECT coalesce(role,''), count(*) FROM endpoint_recognition_summary WHERE first_seen>=$1 AND first_seen<=now() AND coalesce(role,'')<>'' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 8`, start)
	if err != nil {
		return DiscoveryTrends{}, err
	}
	result := DiscoveryTrends{Days: make([]DiscoveryTrendDay, 0, days), AsOf: now, WindowDays: days}
	for typeRows.Next() {
		var item DiscoveryTrendType
		if err = typeRows.Scan(&item.DeviceType, &item.Count); err != nil {
			typeRows.Close()
			return DiscoveryTrends{}, err
		}
		result.TopTypes = append(result.TopTypes, item)
	}
	if err = typeRows.Err(); err != nil {
		typeRows.Close()
		return DiscoveryTrends{}, err
	}
	typeRows.Close()
	for i := 0; i < days; i++ {
		date := start.AddDate(0, 0, i).Format("2006-01-02")
		day, ok := counts[date]
		if !ok {
			day = DiscoveryTrendDay{Date: date}
		}
		result.Days = append(result.Days, day)
	}
	return result, nil
}
