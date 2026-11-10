package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"proxy-sentinel/internal/discovery"
)

// discoveryRecognition is the endpoint-recognition view of a discovered device.
// It is attached beside the discovered facts, never merged into them: a
// fingerprint label and a protocol observation are different classes of
// evidence and the UI must be able to tell them apart.
type discoveryRecognition struct {
	OSFamily           string   `json:"os_family,omitempty"`
	DeviceType         string   `json:"device_type,omitempty"`
	Brand              string   `json:"brand,omitempty"`
	Model              string   `json:"model,omitempty"`
	Confidence         float64  `json:"confidence,omitempty"`
	OSFamilyConfidence float64  `json:"os_family_confidence,omitempty"`
	RuleVersion        string   `json:"rule_version,omitempty"`
	Source             string   `json:"source,omitempty"`
	Evidence           []string `json:"evidence,omitempty"`
	// Brand inference is separate from the device-type conclusion: it can be
	// present while the type stays a clue, so the UI must show its status and
	// confidence instead of presenting it as a confirmed brand.
	BrandInferenceStatus     string  `json:"brand_inference_status,omitempty"`
	BrandInferenceBrand      string  `json:"brand_inference_brand,omitempty"`
	BrandInferenceConfidence float64 `json:"brand_inference_confidence,omitempty"`
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
	rows, err := db.QueryContext(ctx, `SELECT lower(primary_mac),os_family,
CASE WHEN CASE WHEN jsonb_array_length(coalesce(summary->'conflict_dimensions','[]'::jsonb))>0 THEN summary->'conflict_dimensions' ? 'device_type' ELSE conflict END THEN '' ELSE role END,
brand,model,coalesce(NULLIF(summary->>'device_type_confidence','')::double precision,confidence,0),coalesce(NULLIF(summary->>'os_family_confidence','')::double precision,0),rule_version,
coalesce(summary->>'recognition_source',''),coalesce(summary->'recognition_evidence','[]'::jsonb),
coalesce(summary->'brand_inference'->>'status',''),
coalesce(summary->'brand_inference'->>'brand',''),
coalesce(NULLIF(summary->'brand_inference'->>'confidence','')::double precision,0)
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
		var evidence []byte
		if err = rows.Scan(&mac, &item.OSFamily, &item.DeviceType, &item.Brand, &item.Model, &item.Confidence, &item.OSFamilyConfidence, &item.RuleVersion, &item.Source, &evidence, &item.BrandInferenceStatus, &item.BrandInferenceBrand, &item.BrandInferenceConfidence); err != nil {
			fmt.Fprintf(os.Stderr, "discovery recognition row failed: %v\n", err)
			return
		}
		if len(evidence) > 0 {
			_ = json.Unmarshal(evidence, &item.Evidence)
		}
		if len(item.Evidence) > 8 {
			item.Evidence = item.Evidence[:8]
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
	case []discovery.DeviceView:
		// The indexed discovery reader returns typed views. Convert only this
		// bounded page to its JSON shape before adding recognition fields.
		raw, err := json.Marshal(items)
		if err != nil {
			return nil, false
		}
		var out []map[string]any
		if err = json.Unmarshal(raw, &out); err != nil {
			return nil, false
		}
		page["items"] = out
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
			decoration := item
			// Discovery explicitly distinguishes current conclusions from conflicted
			// or expired evidence. A summary decoration must not override that state.
			if state, _ := items[index]["classification_status"].(string); state == "conflict" || state == "expired" {
				decoration.DeviceType = ""
			}
			items[index]["recognition"] = decoration
		}
	}
}

func normalizeDiscoveryMAC(mac string) string {
	return strings.ToLower(strings.TrimSpace(mac))
}
