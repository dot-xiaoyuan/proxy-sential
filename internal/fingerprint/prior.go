package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed data/device-type-prior.json
var embeddedVendorPriors []byte

// VendorPriorTable maps a vendor name to the device class its product line is
// dominated by. It is a fallback for silent endpoints that carry no user agent,
// no mDNS record and no useful hostname; it never confirms a brand or a model.
type VendorPriorTable struct {
	Version   string        `json:"version"`
	Source    string        `json:"source"`
	SourceURL string        `json:"source_url"`
	License   string        `json:"license"`
	Entries   []VendorPrior `json:"entries"`
}

type VendorPrior struct {
	Vendor     string  `json:"vendor"`
	Match      string  `json:"match"`
	DeviceType string  `json:"device_type"`
	Confidence float64 `json:"confidence"`
}

var vendorPriorState = struct {
	sync.RWMutex
	table *VendorPriorTable
}{table: mustLoadVendorPriorTable(embeddedVendorPriors)}

// ParseVendorPriorTable validates a device-type prior table.
func ParseVendorPriorTable(data []byte) (*VendorPriorTable, error) {
	var table VendorPriorTable
	if err := json.Unmarshal(data, &table); err != nil {
		return nil, fmt.Errorf("decode vendor prior table: %w", err)
	}
	if strings.TrimSpace(table.Version) == "" || strings.TrimSpace(table.Source) == "" {
		return nil, fmt.Errorf("vendor prior table requires a version and source")
	}
	clean := make([]VendorPrior, 0, len(table.Entries))
	for index, entry := range table.Entries {
		entry.Vendor = strings.TrimSpace(entry.Vendor)
		entry.DeviceType = strings.TrimSpace(entry.DeviceType)
		entry.Match = strings.ToLower(strings.TrimSpace(entry.Match))
		if entry.Match == "" {
			entry.Match = "contains"
		}
		if entry.Vendor == "" || entry.DeviceType == "" || (entry.Match != "exact" && entry.Match != "contains") {
			return nil, fmt.Errorf("vendor prior entry %d is invalid", index)
		}
		if entry.Confidence <= 0 || entry.Confidence > .80 {
			return nil, fmt.Errorf("vendor prior entry %d confidence must be within (0, 0.80]", index)
		}
		clean = append(clean, entry)
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("vendor prior table contains no entries")
	}
	table.Entries = clean
	return &table, nil
}

// SetVendorPriorTable swaps the process-wide table, mainly for bundles and tests.
func SetVendorPriorTable(table *VendorPriorTable) {
	if table == nil {
		return
	}
	vendorPriorState.Lock()
	vendorPriorState.table = table
	vendorPriorState.Unlock()
}

// LookupVendorPrior returns the device class a vendor's product line implies.
// Exact matches win; otherwise the longest matching "contains" entry is used so
// that "Hangzhou Hikvision Digital Technology" prefers the specific entry.
func LookupVendorPrior(vendor string) (string, float64, bool) {
	needle := strings.ToLower(strings.TrimSpace(vendor))
	if needle == "" {
		return "", 0, false
	}
	vendorPriorState.RLock()
	table := vendorPriorState.table
	vendorPriorState.RUnlock()
	if table == nil {
		return "", 0, false
	}
	best := VendorPrior{}
	for _, entry := range table.Entries {
		candidate := strings.ToLower(entry.Vendor)
		switch entry.Match {
		case "exact":
			if needle == candidate {
				return entry.DeviceType, entry.Confidence, true
			}
		default:
			if !strings.Contains(needle, candidate) {
				continue
			}
			if len(candidate) > len(strings.ToLower(best.Vendor)) {
				best = entry
			}
		}
	}
	if best.DeviceType == "" {
		return "", 0, false
	}
	return best.DeviceType, best.Confidence, true
}

func mustLoadVendorPriorTable(data []byte) *VendorPriorTable {
	table, err := ParseVendorPriorTable(data)
	if err != nil {
		panic(err)
	}
	return table
}
