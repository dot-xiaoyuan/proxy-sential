package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
)

// discoveryRecognition is the endpoint-recognition view of a discovered device.
// It is attached beside the discovered facts, never merged into them: a
// fingerprint label and a protocol observation are different classes of
// evidence and the UI must be able to tell them apart.
type discoveryRecognition struct {
	OSFamily    string  `json:"os_family,omitempty"`
	DeviceType  string  `json:"device_type,omitempty"`
	Brand       string  `json:"brand,omitempty"`
	Model       string  `json:"model,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`
	RuleVersion string  `json:"rule_version,omitempty"`
}

// enrichDiscoveryRecognition joins the terminal recognition summary onto the
// current discovery page by MAC. The read is bounded by the page size, creates
// no rows and leaves devices without a MAC or without a summary untouched.
func enrichDiscoveryRecognition(ctx context.Context, db *sql.DB, page map[string]any) {
	items, ok := discoveryPageItems(page)
	if !ok || len(items) == 0 || db == nil {
		return
	}
	macs, positions := discoveryPageMACs(items)
	if len(macs) == 0 {
		return
	}
	// MACs are lower-case hex with colons, so a text array literal is safe and
	// avoids depending on a driver-specific slice encoding.
	array := "{" + strings.Join(macs, ",") + "}"
	rows, err := db.QueryContext(ctx, `SELECT lower(primary_mac),os_family,role,brand,model,confidence,rule_version
FROM endpoint_recognition_summary
WHERE lower(primary_mac)=ANY($1::text[])
  AND (os_family<>'' OR role<>'' OR brand<>'' OR model<>'')`, array)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery recognition join failed: %v\n", err)
		return
	}
	defer rows.Close()
	found := map[string]discoveryRecognition{}
	for rows.Next() {
		var mac string
		var item discoveryRecognition
		if err = rows.Scan(&mac, &item.OSFamily, &item.DeviceType, &item.Brand, &item.Model, &item.Confidence, &item.RuleVersion); err != nil {
			fmt.Fprintf(os.Stderr, "discovery recognition row failed: %v\n", err)
			return
		}
		found[normalizeDiscoveryMAC(mac)] = item
	}
	applyDiscoveryRecognition(items, positions, found)
}

// discoveryPageItems accepts both slice shapes the discovery repositories use
// so this join never depends on one repository implementation.
func discoveryPageItems(page map[string]any) ([]map[string]any, bool) {
	switch items := page["items"].(type) {
	case []map[string]any:
		return items, true
	case []any:
		out := make([]map[string]any, 0, len(items))
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, item)
		}
		return out, true
	default:
		return nil, false
	}
}

func discoveryPageMACs(items []map[string]any) ([]string, map[string][]int) {
	positions := map[string][]int{}
	macs := make([]string, 0, len(items))
	for index, item := range items {
		mac, _ := item["mac"].(string)
		mac = normalizeDiscoveryMAC(mac)
		if mac == "" {
			continue
		}
		if _, seen := positions[mac]; !seen {
			macs = append(macs, mac)
		}
		positions[mac] = append(positions[mac], index)
	}
	return macs, positions
}

func applyDiscoveryRecognition(items []map[string]any, positions map[string][]int, found map[string]discoveryRecognition) {
	for mac, item := range found {
		for _, index := range positions[mac] {
			if index < 0 || index >= len(items) {
				continue
			}
			items[index]["recognition"] = item
		}
	}
}

func normalizeDiscoveryMAC(mac string) string {
	return strings.ToLower(strings.TrimSpace(mac))
}
