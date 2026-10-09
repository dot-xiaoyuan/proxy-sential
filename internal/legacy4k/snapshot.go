package legacy4k

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

const MaxIdentityAddressRecords = 200000

type OnlineInventory struct {
	InstanceID     string              `json:"instance_id"`
	ObservedAt     time.Time           `json:"observed_at"`
	Rows           []map[string]string `json:"rows"`
	SkippedInvalid int                 `json:"skipped_invalid,omitempty"`
}

type InventoryStats struct {
	Accounts        int `json:"accounts"`
	Sessions        int `json:"sessions"`
	AddressRecords  int `json:"address_records"`
	LoginGeneration int `json:"login_generation"`
	Product         int `json:"product"`
	Group           int `json:"group"`
	MAC             int `json:"mac"`
	Endpoint        int `json:"endpoint"`
}

// Stats validates the complete inventory without materializing address record maps.
func (in OnlineInventory) Stats() (InventoryStats, error) {
	return in.StatsContext(context.Background())
}

// The preliminary bounded list only determines which hashes to read. EXEC reads
// that list again alongside all hashes in one atomic operation. A changed list
// rejects the entire inventory; no partial inventory is ever submitted.
func ReadOnlineInventory(ctx context.Context, client *RedisOnlineClient, list, ready string, maxRecords int) (OnlineInventory, error) {
	if client == nil || !client.Client.Initialized() || list == "" || ready == "" || maxRecords < 1 || maxRecords > 10000 {
		return OnlineInventory{}, fmt.Errorf("explicit online keys and bound (1..10000) required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	endRead, err := client.BeginRead(ctx)
	if err != nil {
		return OnlineInventory{}, err
	}
	defer endRead()
	ids, err := client.LRange(ctx, list, 0, int64(maxRecords)).Result()
	if err != nil {
		return OnlineInventory{}, err
	}
	if len(ids) > maxRecords {
		return OnlineInventory{}, ErrOnlineResourceLimit
	}
	names := []string{"session_id", "rad_online_id", "user_name", "ip", "ipv6", "ip6", "user_mac", "nas_ip", "add_time", "group_id", "products_id", "device_id", "seed_tag"}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			return OnlineInventory{}, fmt.Errorf("invalid or duplicate online list member")
		}
		seen[id] = true
	}
	var current *redis.StringSliceCmd
	var readiness *redis.IntCmd
	var info *redis.StringCmd
	var at *redis.TimeCmd
	hashes := make([]*redis.SliceCmd, len(ids))
	_, err = client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		current = pipe.LRange(ctx, list, 0, int64(maxRecords))
		readiness = pipe.Exists(ctx, ready)
		info = pipe.Info(ctx, "server")
		for i, id := range ids {
			hashes[i] = pipe.HMGet(ctx, "hash:rad_online:"+id, names...)
		}
		at = pipe.Time(ctx)
		return nil
	})
	if err != nil {
		return OnlineInventory{}, err
	}
	if readiness.Val() != 1 {
		return OnlineInventory{}, fmt.Errorf("online source readiness key missing")
	}
	if !slices.Equal(ids, current.Val()) {
		return OnlineInventory{}, fmt.Errorf("online membership changed; retry entire inventory")
	}
	instance := ""
	for _, line := range strings.Split(info.Val(), "\n") {
		if strings.HasPrefix(line, "run_id:") {
			instance = strings.TrimSpace(strings.TrimPrefix(line, "run_id:"))
		}
	}
	result := OnlineInventory{InstanceID: instance, ObservedAt: at.Val().UTC(), Rows: []map[string]string{}}
	for i, hash := range hashes {
		row := map[string]string{}
		for j, value := range hash.Val() {
			if value != nil {
				v, ok := value.(string)
				if !ok {
					return OnlineInventory{}, fmt.Errorf("invalid online hash field")
				}
				if len(v) > MaxOnlineFieldBytes {
					return OnlineInventory{}, ErrOnlineResourceLimit
				}
				row[names[j]] = v
			}
		}
		if row["rad_online_id"] != ids[i] {
			return OnlineInventory{}, ErrOnlineInventoryChanged
		}
		result.Rows = append(result.Rows, row)
	}
	if _, err = result.StatsContext(ctx); err != nil {
		return OnlineInventory{}, err
	}
	return result, nil
}

// ErrOnlineInventoryChanged denotes an interrupted observation, not a broken
// connection. The caller must retry the entire inventory rather than publish it.
var ErrOnlineInventoryChanged = errors.New("online inventory changed or is inconsistent; retry entire inventory")

var onlineInventoryFields = []string{"session_id", "rad_online_id", "user_name", "ip", "ipv6", "ip6", "user_mac", "nas_ip", "add_time", "group_id", "products_id", "control_id", "vlan_id", "device_id", "seed_tag"}

// ReadOnlineInventoryPaged uses bounded read pipelines on one pinned connection,
// then atomically verifies their complete identity projection. A lost connection
// cannot silently rebind the observation to another source instance. No upstream
// business key is written, and no rows are returned on failed validation.
func ReadOnlineInventoryPaged(ctx context.Context, client *RedisOnlineClient, list string, maxRecords, pageSize int) (OnlineInventory, error) {
	if client == nil || !client.Client.Initialized() {
		return OnlineInventory{}, fmt.Errorf("redis client required")
	}
	conn := client.Conn()
	defer conn.Close()
	return readOnlineInventoryPagedConnection(ctx, client, conn, list, maxRecords, pageSize)
}

func readOnlineInventoryPagedConnection(ctx context.Context, client *RedisOnlineClient, conn *redis.Conn, list string, maxRecords, pageSize int) (OnlineInventory, error) {
	if client == nil || !client.Client.Initialized() || conn == nil || strings.TrimSpace(list) == "" || maxRecords < 1 || maxRecords > 100000 || pageSize < 1 || pageSize > 2000 {
		return OnlineInventory{}, fmt.Errorf("redis connection, online list and bounded paging required")
	}
	readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	endRead, err := client.BeginRead(readCtx)
	if err != nil {
		return OnlineInventory{}, err
	}
	defer endRead()
	count, err := conn.LLen(readCtx, list).Result()
	if err != nil {
		return OnlineInventory{}, err
	}
	if count < 0 {
		return OnlineInventory{}, fmt.Errorf("invalid online inventory cardinality")
	}
	if count > int64(maxRecords) {
		return OnlineInventory{}, ErrOnlineResourceLimit
	}
	ids, err := readOnlineMembers(readCtx, conn, list, int(count), pageSize)
	if err != nil {
		return OnlineInventory{}, err
	}
	info, err := conn.Info(readCtx, "server").Result()
	if err != nil {
		return OnlineInventory{}, err
	}
	instance := ""
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, "run_id:") {
			instance = strings.TrimSpace(strings.TrimPrefix(line, "run_id:"))
		}
	}
	if instance == "" {
		return OnlineInventory{}, fmt.Errorf("redis source instance unavailable")
	}
	if len(instance) > 200 {
		return OnlineInventory{}, ErrOnlineResourceLimit
	}
	keys := make([]string, len(ids)+1)
	keys[0] = list
	rows := make([]map[string]string, 0, len(ids))
	projectionBytes := 0
	for start := 0; start < len(ids); start += pageSize {
		if err := readCtx.Err(); err != nil {
			return OnlineInventory{}, err
		}
		end := min(start+pageSize, len(ids))
		pipe := conn.Pipeline()
		commands := make([]*redis.SliceCmd, end-start)
		for i, id := range ids[start:end] {
			keys[start+i+1] = "hash:rad_online:" + id
			commands[i] = pipe.HMGet(readCtx, keys[start+i+1], onlineInventoryFields...)
		}
		if _, err = pipe.Exec(readCtx); err != nil && err != redis.Nil {
			return OnlineInventory{}, err
		}
		for _, command := range commands {
			if len(command.Val()) != len(onlineInventoryFields) {
				return OnlineInventory{}, fmt.Errorf("invalid online hash field count")
			}
			row := map[string]string{}
			for field, value := range command.Val() {
				if value == nil {
					continue
				}
				text, ok := value.(string)
				if !ok {
					return OnlineInventory{}, fmt.Errorf("invalid online hash field")
				}
				if len(text) > MaxOnlineFieldBytes || len(text)+len(onlineInventoryFields[field]) > MaxOnlineProjectionBytes-projectionBytes {
					return OnlineInventory{}, ErrOnlineResourceLimit
				}
				projectionBytes += len(text) + len(onlineInventoryFields[field])
				row[onlineInventoryFields[field]] = text
			}
			rows = append(rows, row)
		}
	}
	if err := readCtx.Err(); err != nil {
		return OnlineInventory{}, err
	}
	// Redis deployments may disable EVAL/EVALSHA. A read-only EXEC compares
	// the complete identity projection at one observation without WATCH, so
	// unrelated accounting writes cannot invalidate healthy identity scans.
	// The transaction is bounded by maxRecords (100000), rather than pageSize.
	var observed *redis.TimeCmd
	var cardinality *redis.IntCmd
	var membership *redis.StringSliceCmd
	validated := make([]*redis.SliceCmd, len(ids))
	_, err = conn.TxPipelined(readCtx, func(pipe redis.Pipeliner) error {
		observed = pipe.Time(readCtx)
		cardinality = pipe.LLen(readCtx, list)
		membership = pipe.LRange(readCtx, list, 0, int64(maxRecords))
		for i := range ids {
			if i%pageSize == 0 {
				if err := readCtx.Err(); err != nil {
					return err
				}
			}
			validated[i] = pipe.HMGet(readCtx, keys[i+1], onlineInventoryFields...)
		}
		return nil
	})
	if err != nil {
		return OnlineInventory{}, err
	}
	if cardinality.Val() != int64(len(ids)) || !slices.Equal(ids, membership.Val()) {
		return OnlineInventory{}, ErrOnlineInventoryChanged
	}
	for i, command := range validated {
		if i%pageSize == 0 {
			if err := readCtx.Err(); err != nil {
				return OnlineInventory{}, err
			}
		}
		if len(command.Val()) != len(onlineInventoryFields) {
			return OnlineInventory{}, fmt.Errorf("invalid online hash field count")
		}
		for field, value := range command.Val() {
			previous, present := rows[i][onlineInventoryFields[field]]
			if value == nil {
				if present {
					return OnlineInventory{}, ErrOnlineInventoryChanged
				}
				continue
			}
			text, ok := value.(string)
			if !ok {
				return OnlineInventory{}, fmt.Errorf("invalid online hash field")
			}
			if !present || text != previous {
				return OnlineInventory{}, ErrOnlineInventoryChanged
			}
		}
	}
	candidate := OnlineInventory{InstanceID: instance, ObservedAt: observed.Val().UTC(), Rows: rows}
	for i, row := range rows {
		if row["rad_online_id"] != ids[i] {
			return OnlineInventory{}, ErrOnlineInventoryChanged
		}
	}
	if _, err = candidate.StatsContext(readCtx); err != nil {
		return OnlineInventory{}, err
	}
	if err := readCtx.Err(); err != nil {
		return OnlineInventory{}, err
	}
	return candidate, nil
}

// ReadOnlineInventoryStabilized tolerates a busy authoritative list without
// ever publishing a partial snapshot. Each round applies membership additions
// and removals, refreshes every surviving identity hash, and then verifies the
// complete ordered membership once more. Members that remain without a hash
// identity through every pass are counted and excluded as stale list entries;
// no partially readable identity record is published. At most maxPasses are
// attempted.
func ReadOnlineInventoryStabilized(ctx context.Context, client *RedisOnlineClient, list string, maxRecords, pageSize, maxPasses int) (OnlineInventory, error) {
	if client == nil || !client.Client.Initialized() || strings.TrimSpace(list) == "" || maxRecords < 1 || maxRecords > 100000 || pageSize < 1 || pageSize > 2000 || maxPasses < 1 || maxPasses > 10 {
		return OnlineInventory{}, fmt.Errorf("redis connection, online list and bounded stabilization required")
	}
	readCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	endRead, err := client.BeginRead(readCtx)
	if err != nil {
		return OnlineInventory{}, err
	}
	defer endRead()
	conn := client.Conn()
	defer conn.Close()
	info, err := conn.Info(readCtx, "server").Result()
	if err != nil {
		return OnlineInventory{}, err
	}
	instance := redisRunID(info)
	if instance == "" || len(instance) > 200 {
		return OnlineInventory{}, fmt.Errorf("redis source instance unavailable")
	}
	rowsByID := map[string]map[string]string{}
	for pass := 0; pass < maxPasses; pass++ {
		count, readErr := conn.LLen(readCtx, list).Result()
		if readErr != nil {
			return OnlineInventory{}, readErr
		}
		if count < 0 || count > int64(maxRecords) {
			return OnlineInventory{}, ErrOnlineResourceLimit
		}
		ids, readErr := readOnlineMembers(readCtx, conn, list, int(count), pageSize)
		if readErr != nil {
			if errors.Is(readErr, ErrOnlineInventoryChanged) {
				continue
			}
			return OnlineInventory{}, readErr
		}
		members := make(map[string]struct{}, len(ids))
		missing := make([]string, 0)
		for _, id := range ids {
			members[id] = struct{}{}
			if _, present := rowsByID[id]; !present {
				missing = append(missing, id)
			}
		}
		for id := range rowsByID {
			if _, present := members[id]; !present {
				delete(rowsByID, id)
			}
		}
		if len(missing) > 0 {
			newRows, rowsErr := readOnlineRowsPartial(readCtx, conn, missing, pageSize)
			if rowsErr != nil {
				return OnlineInventory{}, rowsErr
			}
			for id, row := range newRows {
				rowsByID[id] = row
			}
		}
		verifiedCount, readErr := conn.LLen(readCtx, list).Result()
		if readErr != nil {
			return OnlineInventory{}, readErr
		}
		if verifiedCount != int64(len(ids)) {
			continue
		}
		verifiedIDs, readErr := readOnlineMembers(readCtx, conn, list, len(ids), pageSize)
		if readErr != nil || !slices.Equal(ids, verifiedIDs) {
			continue
		}
		observed, readErr := conn.Time(readCtx).Result()
		if readErr != nil {
			return OnlineInventory{}, readErr
		}
		rows := make([]map[string]string, 0, len(ids))
		complete := true
		for _, id := range ids {
			row, present := rowsByID[id]
			if !present || row["rad_online_id"] != id {
				complete = false
				break
			}
			rows = append(rows, row)
		}
		if !complete && pass < maxPasses-1 {
			continue
		}
		if !complete {
			rows = rows[:0]
			for _, id := range ids {
				if row, present := rowsByID[id]; present && row["rad_online_id"] == id {
					rows = append(rows, row)
				}
			}
			if len(ids) > 0 && len(rows) == 0 {
				continue
			}
		}
		candidate := OnlineInventory{InstanceID: instance, ObservedAt: observed.UTC(), Rows: rows, SkippedInvalid: len(ids) - len(rows)}
		if _, readErr = candidate.StatsContext(readCtx); readErr != nil {
			if errors.Is(readErr, ErrOnlineInventoryChanged) {
				continue
			}
			return OnlineInventory{}, readErr
		}
		return candidate, nil
	}
	return OnlineInventory{}, ErrOnlineInventoryChanged
}

// readOnlineRowsPartial omits list members whose hash was removed or reused
// while the page was being read. The next stabilization pass re-evaluates
// membership and retries only those unresolved IDs.
func readOnlineRowsPartial(ctx context.Context, conn *redis.Conn, ids []string, pageSize int) (map[string]map[string]string, error) {
	rows := make(map[string]map[string]string, len(ids))
	projectionBytes := 0
	for start := 0; start < len(ids); start += pageSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(start+pageSize, len(ids))
		pipe := conn.Pipeline()
		commands := make([]*redis.SliceCmd, end-start)
		for i, id := range ids[start:end] {
			commands[i] = pipe.HMGet(ctx, "hash:rad_online:"+id, onlineInventoryFields...)
		}
		if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
			return nil, err
		}
		for index, command := range commands {
			values := command.Val()
			if len(values) != len(onlineInventoryFields) {
				return nil, fmt.Errorf("invalid online hash field count")
			}
			row := map[string]string{}
			for field, value := range values {
				if value == nil {
					continue
				}
				valueString, ok := value.(string)
				if !ok || len(valueString) > MaxOnlineFieldBytes || len(valueString)+len(onlineInventoryFields[field]) > MaxOnlineProjectionBytes-projectionBytes {
					return nil, ErrOnlineResourceLimit
				}
				projectionBytes += len(valueString) + len(onlineInventoryFields[field])
				row[onlineInventoryFields[field]] = valueString
			}
			id := ids[start+index]
			if row["rad_online_id"] == id {
				rows[id] = row
			}
		}
	}
	return rows, nil
}

func redisRunID(info string) string {
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, "run_id:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "run_id:"))
		}
	}
	return ""
}

func readOnlineRows(ctx context.Context, conn *redis.Conn, ids []string, pageSize int) ([]map[string]string, error) {
	rows := make([]map[string]string, 0, len(ids))
	projectionBytes := 0
	for start := 0; start < len(ids); start += pageSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(start+pageSize, len(ids))
		pipe := conn.Pipeline()
		commands := make([]*redis.SliceCmd, end-start)
		for i, id := range ids[start:end] {
			commands[i] = pipe.HMGet(ctx, "hash:rad_online:"+id, onlineInventoryFields...)
		}
		if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
			return nil, err
		}
		for i, command := range commands {
			values := command.Val()
			if len(values) != len(onlineInventoryFields) {
				return nil, fmt.Errorf("invalid online hash field count")
			}
			row := map[string]string{}
			for field, value := range values {
				if value == nil {
					continue
				}
				valueString, ok := value.(string)
				if !ok || len(valueString) > MaxOnlineFieldBytes || len(valueString)+len(onlineInventoryFields[field]) > MaxOnlineProjectionBytes-projectionBytes {
					return nil, ErrOnlineResourceLimit
				}
				projectionBytes += len(valueString) + len(onlineInventoryFields[field])
				row[onlineInventoryFields[field]] = valueString
			}
			if row["rad_online_id"] != ids[start+i] {
				return nil, ErrOnlineInventoryChanged
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func readOnlineMembers(ctx context.Context, client redis.Cmdable, list string, count, pageSize int) ([]string, error) {
	ids := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	for start := 0; start < count; start += pageSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(start+pageSize, count)
		page, err := client.LRange(ctx, list, int64(start), int64(end-1)).Result()
		if err != nil {
			return nil, err
		}
		if len(page) != end-start {
			return nil, ErrOnlineInventoryChanged
		}
		for _, id := range page {
			if len(id) > MaxOnlineFieldBytes {
				return nil, ErrOnlineResourceLimit
			}
			if id == "" {
				return nil, fmt.Errorf("invalid online list member")
			}
			if _, ok := seen[id]; ok {
				return nil, fmt.Errorf("duplicate online list member")
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

type onlineIdentityRow struct {
	row       map[string]string
	id        string
	account   string
	login     string
	key       string
	addresses [3]netip.Addr
	count     int
}

// walkIdentityRows is the shared validation boundary for counting and expansion.
// Neither path may skip source bounds, address aliases or session-key collisions.
func (in OnlineInventory) walkIdentityRows(ctx context.Context, visit func(onlineIdentityRow)) (InventoryStats, error) {
	if err := ctx.Err(); err != nil {
		return InventoryStats{}, err
	}
	if len(in.InstanceID) > 200 {
		return InventoryStats{}, ErrOnlineResourceLimit
	}
	if err := validateOnlineProjectionContext(ctx, in.Rows); err != nil {
		return InventoryStats{}, err
	}
	if in.InstanceID == "" || in.ObservedAt.IsZero() {
		return InventoryStats{}, fmt.Errorf("source instance and observation time required")
	}
	seen := make(map[string]struct{}, len(in.Rows))
	accounts := make(map[string]struct{}, min(len(in.Rows), 1000))
	stats := InventoryStats{}
	for i, row := range in.Rows {
		if err := ctx.Err(); err != nil {
			return InventoryStats{}, err
		}
		parsed := onlineIdentityRow{row: row, id: first(row, "session_id", "rad_online_id"), account: first(row, "user_name", "username"), login: row["add_time"]}
		for _, field := range []string{"ip", "ipv6", "ip6"} {
			value := row[field]
			if value == "" {
				continue
			}
			ip, err := netip.ParseAddr(value)
			if err != nil || ip.Zone() != "" || ip.IsMulticast() {
				return InventoryStats{}, fmt.Errorf("online record %d has invalid %s", i+1, field)
			}
			if ip.IsUnspecified() {
				continue
			}
			ip = ip.Unmap()
			if !slices.Contains(parsed.addresses[:parsed.count], ip) {
				parsed.addresses[parsed.count] = ip
				parsed.count++
			}
		}
		if parsed.id == "" || parsed.account == "" || parsed.count == 0 {
			return InventoryStats{}, fmt.Errorf("online record %d lacks valid account, session or IP", i+1)
		}
		if parsed.login != "" {
			seconds, err := strconv.ParseInt(parsed.login, 10, 64)
			if err != nil || seconds <= 0 || strconv.FormatInt(seconds, 10) != parsed.login || time.Unix(seconds, 0).After(in.ObservedAt) {
				return InventoryStats{}, fmt.Errorf("online record %d has invalid login generation", i+1)
			}
		}
		parsed.key = OnlineSessionID(in.InstanceID, parsed.id, parsed.login)
		if _, exists := seen[parsed.key]; exists {
			return InventoryStats{}, fmt.Errorf("duplicate online session at record %d", i+1)
		}
		seen[parsed.key] = struct{}{}
		if parsed.count > MaxIdentityAddressRecords-stats.AddressRecords {
			return InventoryStats{}, fmt.Errorf("expanded address inventory exceeds %d records", MaxIdentityAddressRecords)
		}
		stats.Sessions++
		stats.AddressRecords += parsed.count
		accounts[parsed.account] = struct{}{}
		if parsed.login != "" {
			stats.LoginGeneration++
		}
		if row["products_id"] != "" {
			stats.Product++
		}
		if row["group_id"] != "" {
			stats.Group++
		}
		if first(row, "user_mac", "mac") != "" {
			stats.MAC++
		}
		if row["device_id"] != "" {
			stats.Endpoint++
		}
		if visit != nil {
			visit(parsed)
		}
	}
	if err := ctx.Err(); err != nil {
		return InventoryStats{}, err
	}
	stats.Accounts = len(accounts)
	return stats, nil
}

func (in OnlineInventory) IdentityRecords() ([]map[string]string, error) {
	records, _, err := in.IdentityRecordsWithStats()
	return records, err
}

// IdentityRecordsWithStats expands once and returns the summary from that same
// validated walk. Failed validation returns neither partial records nor counts.
func (in OnlineInventory) IdentityRecordsWithStats() ([]map[string]string, InventoryStats, error) {
	return in.IdentityRecordsWithStatsContext(context.Background())
}

// Cancellation is checked during projection validation and each source row.
// A failed or interrupted walk never exposes partial records or coverage.
func (in OnlineInventory) IdentityRecordsWithStatsContext(ctx context.Context) ([]map[string]string, InventoryStats, error) {
	out := []map[string]string{}
	stats, err := in.walkIdentityRows(ctx, func(parsed onlineIdentityRow) {
		if cap(out) == 0 {
			out = make([]map[string]string, 0, min(len(in.Rows)*2, MaxIdentityAddressRecords))
		}
		row := parsed.row
		mac := first(row, "user_mac", "mac")
		for _, ip := range parsed.addresses[:parsed.count] {
			out = append(out, map[string]string{"account_id": parsed.account, "ip": ip.String(), "session_id": parsed.key, "source_session_id": parsed.id, "raw_online_id": row["rad_online_id"], "source_login_generation": parsed.login, "session_id_source": "derived_source_session_login", "mac": mac, "nas_ip": row["nas_ip"], "endpoint_id": row["device_id"], "group_id": row["group_id"], "product_id": row["products_id"], "source_instance_id": in.InstanceID, "vlan": row["vlan_id"], "control_id": row["control_id"]})
		}
	})
	if err != nil {
		return nil, InventoryStats{}, err
	}
	return out, stats, nil
}

func (s Sender) SendSnapshot(ctx context.Context, in OnlineInventory, source, campus, domain string, interval int) error {
	records, err := in.IdentityRecords()
	if err != nil {
		return err
	}
	if source == "" || s.SensorID == "" || campus == "" || domain == "" || interval < 1 || interval > 86400 {
		return fmt.Errorf("explicit snapshot authority scope and interval required")
	}
	body, err := json.Marshal(map[string]any{"source": source, "sensor_id": s.SensorID, "campus_id": campus, "access_domain": domain, "observed_at": in.ObservedAt, "reconcile_interval_seconds": interval, "complete": true, "expected_count": len(records), "records": records})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.Endpoint, "/")+"/api/v1/integrations/identity/snapshots", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", StableID(string(body)))
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusAccepted && res.StatusCode != http.StatusOK {
		var detail struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&detail) == nil && detail.Code == "bad_identity_snapshot" && detail.Message == "observed_at must be within the past seven days with at most microsecond precision" {
			return fmt.Errorf("identity snapshot endpoint returned %s: observation timestamp rejected; verify source clock and pending inventory age", res.Status)
		}
		return fmt.Errorf("identity snapshot endpoint returned %s", res.Status)
	}
	var ack struct {
		Status string `json:"status"`
		ID     string `json:"snapshot_id"`
		Count  int    `json:"session_count"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&ack); err != nil {
		return fmt.Errorf("invalid inventory acknowledgement")
	}
	if ack.Status != "completed" || ack.ID != StableID(string(body)) || ack.Count != len(records) {
		return fmt.Errorf("inventory acknowledgement mismatch")
	}
	return nil
}
