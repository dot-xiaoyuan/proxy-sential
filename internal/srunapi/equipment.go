package srunapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EquipmentObservation is a bounded, account-filtered observation. The legacy
// endpoint has no atomic snapshot or absence contract, even when it returns [].
// Raw fields are retained for diagnosis; callers must not log the full inventory.
type EquipmentObservation struct {
	Rows            []map[string]string `json:"rows"`
	ObservedAt      time.Time           `json:"observed_at"`
	Complete        bool                `json:"complete"`
	AbsenceVerified bool                `json:"absence_verified"`
	Blocker         string              `json:"blocker"`
}

func (c *Client) OnlineEquipment(ctx context.Context, account string) (EquipmentObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	result := EquipmentObservation{Rows: []map[string]string{}, Blocker: "inventory_completeness_unproven"}
	if account == "" || strings.TrimSpace(account) != account || len(account) > 256 {
		return result, fmt.Errorf("explicit account filter required")
	}
	token, err := c.authenticate(ctx)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrAuthentication, err)
	}
	data, err := c.postBounded(ctx, "/api/v2/base/online-equipment", url.Values{"access_token": {token}, "user_name": {account}}, 16<<20)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrReadOnlyQuery, err)
	}
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '[' {
		return result, fmt.Errorf("%w: equipment is not a session array", ErrReadOnlyQuery)
	}
	var rows []map[string]json.RawMessage
	if json.Unmarshal(data, &rows) != nil || len(rows) > 10000 {
		return result, fmt.Errorf("%w: invalid or oversized equipment inventory", ErrReadOnlyQuery)
	}
	result.ObservedAt = time.Now().UTC()
	seen := map[string]bool{}
	for _, raw := range rows {
		row := map[string]string{}
		for key, value := range raw {
			var text string
			if json.Unmarshal(value, &text) == nil {
				row[key] = text
				continue
			}
			var n json.Number
			dec := json.NewDecoder(bytes.NewReader(value))
			dec.UseNumber()
			if dec.Decode(&n) == nil {
				if _, err := n.Int64(); err == nil {
					row[key] = n.String()
					continue
				}
			}
			if string(value) == "null" {
				row[key] = ""
				continue
			}
			return result, fmt.Errorf("%w: unsupported equipment field type", ErrReadOnlyQuery)
		}
		if row["ip"] == "" {
			row["ip"] = row["user_ip"]
		} else if row["user_ip"] != "" && row["user_ip"] != row["ip"] {
			return result, fmt.Errorf("%w: conflicting equipment IP fields", ErrReadOnlyQuery)
		}
		result.Rows = append(result.Rows, row)
		login, err := strconv.ParseInt(row["add_time"], 10, 64)
		ip, ipErr := netip.ParseAddr(row["ip"])
		if row["user_name"] != account || row["rad_online_id"] == "" || strings.TrimSpace(row["rad_online_id"]) != row["rad_online_id"] || err != nil || login <= 0 || strconv.FormatInt(login, 10) != row["add_time"] || time.Unix(login, 0).After(result.ObservedAt) || ipErr != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return result, fmt.Errorf("%w: equipment identity invalid (account_match=%t raw_id_present=%t login_parse=%t login_positive=%t login_canonical=%t login_future=%t ip_valid=%t)", ErrReadOnlyQuery, row["user_name"] == account, row["rad_online_id"] != "", err == nil, login > 0, strconv.FormatInt(login, 10) == row["add_time"], time.Unix(login, 0).After(result.ObservedAt), ipErr == nil)
		}
		if seen[row["rad_online_id"]] {
			return result, fmt.Errorf("%w: duplicate equipment identity", ErrReadOnlyQuery)
		}
		seen[row["rad_online_id"]] = true
	}
	return result, nil
}
