package discovery

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// The ranked reader accelerates ordinary cursor pages. It reads only current
// structured facts and uses the existing classifier for every admission.
func orderedPageEnabled(q DeviceQuery) bool {
	return q.structured && !q.orderedPageDisabled && structuredReadEnabled("ordered_pages") && structuredReadEnabled("address_links") &&
		q.Mode == "passive" && !q.Export && q.View == "" && q.Search == "" && q.Protocol == "" && q.State == "" && q.Domain == "" && q.VLAN == "" &&
		q.ReviewReason == "" && q.Category == "" && q.OSFamily == "" && q.Capability == "" && !q.RandomMAC && q.Subnet == "" && q.FirstSeenWithin == 0 &&
		q.LastSeenFrom.IsZero() && q.LastSeenTo.IsZero()
}

type pageKeySource uint8

const (
	pageIdentityKeys pageKeySource = iota
	pageBaseIdentityKeys
	pageTupleLocators
)

type pageSighting struct {
	key  string
	seen time.Time
}

func readPageKeys(ctx context.Context, db indexedQueryer, statement string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

// A verified profile/DHCP role requires a usable, matching source MAC. IP
// product clues can move to a linked identity and go through forward resolution.
func typedPageKeys(ctx context.Context, db indexedQueryer, q DeviceQuery, cap int) ([]string, bool, error) {
	types := strings.Split(q.DeviceType, ",")
	if slices.Contains(types, "") {
		return nil, false, nil
	}
	branches := []struct {
		sql  string
		base bool
	}{
		{`SELECT identity_key COLLATE "C" FROM passive_hardware_current WHERE hardware_type<>'' AND hardware_type=ANY($1)`, false},
		{`SELECT f.base_identity FROM endpoint_recognition_summary r CROSS JOIN LATERAL (
    SELECT DISTINCT o.base_identity FROM discovery_list_observation o WHERE lower(o.raw_mac)=substring(lower(r.endpoint_id) FROM 5)
    AND o.observed_at BETWEEN $3 AND now() ORDER BY o.base_identity LIMIT $2
   ) f WHERE r.role=ANY($1) AND lower(r.endpoint_id) LIKE 'mac:%' AND r.last_seen BETWEEN $3 AND now()`, false},
		{`SELECT base_identity FROM discovery_list_observation WHERE origin IN ('dhcp','dhcp_client') AND dhcp_type<>'' AND dhcp_type=ANY($1)
    AND valid_until>now() AND observed_at BETWEEN $3 AND now()`, false},
		{`SELECT base_identity FROM discovery_list_observation WHERE product_status='identified' AND product_type<>'' AND product_type=ANY($1)
    AND valid_until>now() AND observed_at BETWEEN $3 AND now()`, true},
	}
	keys := []string{}
	for i, branch := range branches {
		args := []any{types, cap + 1}
		if i != 0 {
			args = append(args, q.SnapshotAt.Add(-q.Window))
		}
		found, err := readPageKeys(ctx, db, branch.sql+" LIMIT $2", args...)
		if err != nil {
			return nil, false, err
		}
		if len(found) > cap {
			return nil, false, nil
		}
		if branch.base && len(found) > 0 {
			found, err = resolvePageSeeds(ctx, db, q, found, cap+1, pageBaseIdentityKeys)
			if err != nil {
				return nil, false, err
			}
		}
		keys = append(keys, found...)
		if len(keys) > cap {
			return nil, false, nil
		}
	}
	sort.Strings(keys)
	return slices.Compact(keys), true, nil
}

func resolvePageSeeds(ctx context.Context, db indexedQueryer, q DeviceQuery, base []string, limit int, source pageKeySource) ([]string, error) {
	// The resolved identity comes from exactly the same scoped link/lease/SADP
	// rules used by the final page; evidence and profiles are not needed here.
	q.pageKeys, q.pageKeySource = base, source
	q.DeviceType = ""
	s, err := buildIndexedDeviceSelection(q)
	if err != nil {
		return nil, err
	}
	tail := " SELECT DISTINCT identity_key FROM seed_rows"
	if limit > 0 {
		tail += fmt.Sprintf(" LIMIT %d", limit)
	}
	return readPageKeys(ctx, db, s.CTE+tail, s.Args...)
}

func rankPageKeys(ctx context.Context, db indexedQueryer, q DeviceQuery, keys []string, position *indexedDeviceCursor) ([]pageSighting, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	q.pageKeys = keys
	s, err := buildIndexedDeviceSelection(q)
	if err != nil {
		return nil, err
	}
	args := s.Args
	where := ""
	if position != nil {
		seen, _ := time.Parse(time.RFC3339Nano, position.LastSeen)
		args = append(args, seen, position.IdentityKey)
		where = fmt.Sprintf(` WHERE last_seen<$%d OR (last_seen=$%d AND identity_key COLLATE "C">$%d)`, len(args)-1, len(args)-1, len(args))
	}
	args = append(args, q.Limit+1)
	source := "matched"
	if crossVLAN(q) {
		source = "(SELECT identity_key,asset_last_seen last_seen FROM matched) assets"
	}
	rows, err := db.QueryContext(ctx, s.CTE+" SELECT identity_key,last_seen FROM "+source+where+fmt.Sprintf(` ORDER BY last_seen DESC,identity_key COLLATE "C" LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []pageSighting
	for rows.Next() {
		var item pageSighting
		if err := rows.Scan(&item.key, &item.seen); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func orderedDeviceKeys(ctx context.Context, db indexedQueryer, q DeviceQuery, position *indexedDeviceCursor) ([]string, error) {
	wanted := q.Limit + 1
	batch := max(64, 2*wanted)
	if q.DeviceType != "" {
		keys, small, err := typedPageKeys(ctx, db, q, max(256, 4*wanted))
		if err != nil {
			return nil, err
		}
		if small {
			ranked, err := rankPageKeys(ctx, db, q, keys, position)
			if err != nil {
				return nil, err
			}
			return sightingKeys(ranked), nil
		}
	}
	// Seek raw base sightings by their descending time. A group's true last_seen
	// is necessarily one of its member sightings. On the first chunk of a cursor
	// page all equal-time BASE keys must be included, because links can rename one.
	var after pageSighting
	var tuple string
	if position != nil {
		after.seen, _ = time.Parse(time.RFC3339Nano, position.LastSeen)
	}
	lower := q.SnapshotAt.Add(-q.Window)
	best := []pageSighting{}
	visited := map[string]struct{}{}
	for {
		args := []any{lower, batch}
		where := ""
		if !after.seen.IsZero() {
			args = append(args, after.seen)
			where = " AND observed_at<=$3"
			if after.key != "" {
				args = append(args, after.key, tuple)
				where += ` AND (observed_at<$3 OR (base_identity,ctid)>($4 COLLATE "C",$5::tid))`
			}
		}
		rows, err := db.QueryContext(ctx, `SELECT observed_at,base_identity,ctid::text FROM discovery_list_observation
   WHERE observed_at BETWEEN $1 AND now()`+where+` ORDER BY observed_at DESC,base_identity,ctid LIMIT $2`, args...)
		if err != nil {
			return nil, err
		}
		bases := []string{}
		n := 0
		for rows.Next() {
			if err = rows.Scan(&after.seen, &after.key, &tuple); err != nil {
				rows.Close()
				return nil, err
			}
			bases = append(bases, tuple)
			n++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		keys, err := resolvePageSeeds(ctx, db, q, bases, 0, pageTupleLocators)
		if err != nil {
			return nil, err
		}
		if crossVLAN(q) {
			keys, err = unrankedVLANSeeds(ctx, db, q, keys, visited, max(4096, 4*batch))
			if err != nil {
				return nil, err
			}
		}
		ranked, err := rankPageKeys(ctx, db, q, keys, position)
		if err != nil {
			return nil, err
		}
		best = append(best, ranked...)
		sort.Slice(best, func(i, j int) bool {
			if best[i].seen.Equal(best[j].seen) {
				return best[i].key < best[j].key
			}
			return best[i].seen.After(best[j].seen)
		})
		best = slices.CompactFunc(best, func(a, b pageSighting) bool { return a.key == b.key })
		if len(best) > wanted {
			best = best[:wanted]
		}
		if n < batch || (len(best) == wanted && best[wanted-1].seen.After(after.seen)) {
			break
		}
	}
	return sightingKeys(best), nil
}

func sightingKeys(items []pageSighting) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.key)
	}
	return keys
}
