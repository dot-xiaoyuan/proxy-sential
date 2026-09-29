package legacy4k

import (
	"bytes"
	"context"
	"encoding/json"
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

type OnlineInventory struct {
	InstanceID string              `json:"instance_id"`
	ObservedAt time.Time           `json:"observed_at"`
	Rows       []map[string]string `json:"rows"`
}

// The preliminary bounded list only determines which hashes to read. EXEC reads
// that list again alongside all hashes in one atomic operation. A changed list
// rejects the entire inventory; no partial inventory is ever submitted.
func ReadOnlineInventory(ctx context.Context, client *redis.Client, list, ready string, maxRecords int) (OnlineInventory, error) {
	if list == "" || ready == "" || maxRecords < 1 || maxRecords > 10000 {
		return OnlineInventory{}, fmt.Errorf("explicit online keys and bound (1..10000) required")
	}
	ids, err := client.LRange(ctx, list, 0, int64(maxRecords)).Result()
	if err != nil {
		return OnlineInventory{}, err
	}
	if len(ids) > maxRecords {
		return OnlineInventory{}, fmt.Errorf("online inventory exceeds configured bound")
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
				row[names[j]] = v
			}
		}
		if row["rad_online_id"] != ids[i] {
			return OnlineInventory{}, fmt.Errorf("online hash missing or identity differs from list")
		}
		result.Rows = append(result.Rows, row)
	}
	_, err = result.IdentityRecords()
	return result, err
}
func (in OnlineInventory) IdentityRecords() ([]map[string]string, error) {
	if in.InstanceID == "" || in.ObservedAt.IsZero() {
		return nil, fmt.Errorf("source instance and observation time required")
	}
	out := []map[string]string{}
	seen := map[string]bool{}
	for i, row := range in.Rows {
		id := first(row, "session_id", "rad_online_id")
		account := first(row, "user_name", "username")
		addresses := []netip.Addr{}
		seenAddresses := map[netip.Addr]bool{}
		for _, field := range []string{"ip", "ipv6", "ip6"} {
			value := row[field]
			if value == "" {
				continue
			}
			ip, err := netip.ParseAddr(value)
			if err != nil || ip.Zone() != "" || ip.IsMulticast() {
				return nil, fmt.Errorf("online record %d has invalid %s", i+1, field)
			}
			if ip.IsUnspecified() {
				continue
			}
			ip = ip.Unmap()
			if !seenAddresses[ip] {
				addresses = append(addresses, ip)
				seenAddresses[ip] = true
			}
		}
		if id == "" || account == "" || len(addresses) == 0 {
			return nil, fmt.Errorf("online record %d lacks valid account, session or IP", i+1)
		}

		login := row["add_time"]
		if login != "" {
			seconds, err := strconv.ParseInt(login, 10, 64)
			if err != nil || seconds <= 0 || strconv.FormatInt(seconds, 10) != login || time.Unix(seconds, 0).After(in.ObservedAt) {
				return nil, fmt.Errorf("online record %d has invalid login generation", i+1)
			}
		}
		key := OnlineSessionID(in.InstanceID, id, login)
		if seen[key] {
			return nil, fmt.Errorf("duplicate online session at record %d", i+1)
		}
		seen[key] = true
		for _, ip := range addresses {
			record := map[string]string{"account_id": account, "ip": ip.String(), "session_id": key, "source_session_id": id, "raw_online_id": row["rad_online_id"], "source_login_generation": login, "session_id_source": "derived_source_session_login", "mac": first(row, "user_mac", "mac"), "nas_ip": row["nas_ip"], "endpoint_id": row["device_id"], "group_id": row["group_id"], "product_id": row["products_id"], "source_instance_id": in.InstanceID}
			out = append(out, record)
			if len(out) > 10000 {
				return nil, fmt.Errorf("expanded address inventory exceeds 10000 records")
			}
		}
	}
	return out, nil
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
