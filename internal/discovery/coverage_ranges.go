package discovery

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// PlannedIPv4Report counts observed addresses in operator-specified ranges.
// The device type is a planning label, independent of observed identity.
type PlannedIPv4Report struct {
	Status         string             `json:"status"`
	Version        string             `json:"version,omitempty"`
	CaptureVersion string             `json:"capture_version,omitempty"`
	AvailableFrom  *time.Time         `json:"available_from,omitempty"`
	AsOf           *time.Time         `json:"as_of,omitempty"`
	VisibleIPv4    *int64             `json:"visible_ipv4,omitempty"`
	Ranges         []PlannedIPv4Range `json:"ranges,omitempty"`
}

type PlannedIPv4Range struct {
	Range       string `json:"range"`
	DeviceType  string `json:"device_type"`
	VisibleIPv4 int64  `json:"visible_ipv4"`
}

type reportRange struct {
	Range      string `json:"range"`
	DeviceType string `json:"device_type"`
	Low        string `json:"low"`
	High       string `json:"high"`
}

func rangeBounds(raw string) (netip.Addr, netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		if !prefix.Addr().Is4() || prefix.Masked() != prefix {
			return netip.Addr{}, netip.Addr{}, errors.New("需要完整的 IPv4 网络前缀")
		}
		low := prefix.Addr().As4()
		high := low
		hostMask := ^uint32(0) >> prefix.Bits()
		binary.BigEndian.PutUint32(high[:], binary.BigEndian.Uint32(low[:])|hostMask)
		return prefix.Addr(), netip.AddrFrom4(high), nil
	}
	first, last, interval := strings.Cut(raw, "-")
	if !interval {
		last = first
	}
	low, e1 := netip.ParseAddr(first)
	high, e2 := netip.ParseAddr(last)
	if e1 != nil || e2 != nil || !low.Is4() || !high.Is4() || low.Compare(high) > 0 {
		return netip.Addr{}, netip.Addr{}, errors.New("需要 IPv4 地址、网络前缀或升序闭区间")
	}
	return low, high, nil
}

func parseReportRanges(raw string) ([]reportRange, string, error) {
	var definitions []struct {
		Range      string `json:"range"`
		DeviceType string `json:"device_type"`
	}
	if err := json.Unmarshal([]byte(raw), &definitions); err != nil {
		return nil, "", err
	}
	if len(definitions) == 0 || len(definitions) > 128 {
		return nil, "", errors.New("报表范围应为 1 到 128 条")
	}
	ranges := make([]reportRange, 0, len(definitions))
	keys := make([]string, 0, len(definitions))
	for i, def := range definitions {
		name, label := strings.TrimSpace(def.Range), strings.TrimSpace(def.DeviceType)
		low, high, err := rangeBounds(name)
		if err != nil || label == "" || len(label) > 256 {
			return nil, "", fmt.Errorf("报表范围第 %d 行的地址或规划类型无效", i+1)
		}
		ranges = append(ranges, reportRange{Range: name, DeviceType: label, Low: low.String(), High: high.String()})
		key, _ := json.Marshal([]string{low.String(), high.String(), label})
		keys = append(keys, string(key))
	}
	sort.Strings(keys)
	for i := 1; i < len(keys); i++ {
		if keys[i] == keys[i-1] {
			return nil, "", errors.New("报表范围含有重复行")
		}
	}
	sum := sha256.Sum256([]byte("planned-ipv4/v1\n" + strings.Join(keys, "\n")))
	return ranges, hex.EncodeToString(sum[:]), nil
}

// One snapshot uses the census event watermark for both ends of the window.
// Distinct IPv4 values collapse multiple VLANs. The final DISTINCT also
// collapses addresses that belong to multiple planned ranges.
func readPlannedIPv4(ctx context.Context, db *sql.DB, sensor string, window time.Duration, raw string) (*PlannedIPv4Report, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	ranges, version, err := parseReportRanges(raw)
	if err != nil {
		return &PlannedIPv4Report{Status: "configuration_error"}, err
	}
	result := &PlannedIPv4Report{Version: version, Status: "unavailable"}
	input, err := json.Marshal(ranges)
	if err != nil {
		return result, err
	}
	const query = `WITH state AS MATERIALIZED (
 SELECT scope_version,available_from,last_source_at,last_success_at,oldest_pending_at FROM passive_census_runtime WHERE sensor_id=$1
), observed AS MATERIALIZED (
 SELECT DISTINCT i.value::inet ip FROM passive_census_identifier_current i CROSS JOIN state s
 WHERE i.sensor_id=$1 AND i.kind='ip' AND i.ip_family=4
 AND i.last_seen BETWEEN greatest(s.last_source_at-($2 * interval '1 second'),s.available_from) AND s.last_source_at
), matches AS MATERIALIZED (
 SELECT r.n,i.ip FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS r(value,n)
 JOIN observed i ON i.ip BETWEEN (r.value->>'low')::inet AND (r.value->>'high')::inet
), counts AS (SELECT n,count(*) AS count FROM matches GROUP BY n)
SELECT scope_version,available_from,last_source_at,last_success_at,oldest_pending_at,
 (SELECT count(DISTINCT ip) FROM matches),(SELECT coalesce(jsonb_object_agg(n,count),'{}') FROM counts)
 FROM state`
	var source, available, success, pending sql.NullTime
	var total int64
	var data []byte
	err = db.QueryRowContext(ctx, query, sensor, int64(window/time.Second), input).Scan(&result.CaptureVersion, &available, &source, &success, &pending, &total, &data)
	if errors.Is(err, sql.ErrNoRows) {
		result.Status = "initializing"
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if available.Valid {
		result.AvailableFrom = &available.Time
	}
	if !source.Valid {
		result.Status = "initializing"
		return result, nil
	}
	result.AsOf = &source.Time
	var counts map[int]int64
	if err = json.Unmarshal(data, &counts); err != nil {
		return result, err
	}
	result.Status = "ready"
	if !available.Valid || available.Time.After(source.Time.Add(-window)) || pending.Valid {
		result.Status = "partial"
	}
	if success.Valid && time.Since(success.Time) > 10*time.Minute {
		result.Status = "delayed"
	}
	result.VisibleIPv4 = &total
	for i, r := range ranges {
		result.Ranges = append(result.Ranges, PlannedIPv4Range{Range: r.Range, DeviceType: r.DeviceType, VisibleIPv4: counts[i+1]})
	}
	return result, nil
}
