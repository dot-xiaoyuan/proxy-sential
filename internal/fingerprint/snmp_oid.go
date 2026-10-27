package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed data/snmp-enterprise-oid.json
var embeddedSNMPOIDs []byte

// SNMPVendorConfidence is the confidence of a vendor resolved from a device's
// self-reported sysObjectID. It is lower than an exact model match and higher
// than a bare MAC OUI: the device names its own vendor, but the OID identifies
// the vendor company, not the hardware model.
const SNMPVendorConfidence = 0.85

// SNMPOIDTable maps IANA private enterprise numbers to the organisation that
// registered them. Keys are the enterprise number without the leading prefix.
type SNMPOIDTable struct {
	Version   string            `json:"version"`
	Source    string            `json:"source"`
	SourceURL string            `json:"source_url"`
	Prefix    string            `json:"prefix"`
	License   string            `json:"license"`
	Entries   map[string]string `json:"entries"`
}

var snmpOIDState = struct {
	sync.RWMutex
	table *SNMPOIDTable
}{table: mustLoadSNMPOIDTable(embeddedSNMPOIDs)}

// ParseSNMPOIDTable validates an enterprise-number table.
func ParseSNMPOIDTable(data []byte) (*SNMPOIDTable, error) {
	var table SNMPOIDTable
	if err := json.Unmarshal(data, &table); err != nil {
		return nil, fmt.Errorf("decode SNMP OID table: %w", err)
	}
	if strings.TrimSpace(table.Version) == "" || strings.TrimSpace(table.Source) == "" {
		return nil, fmt.Errorf("SNMP OID table requires a version and source")
	}
	if len(table.Entries) == 0 {
		return nil, fmt.Errorf("SNMP OID table contains no entries")
	}
	clean := make(map[string]string, len(table.Entries))
	for number, vendor := range table.Entries {
		key := strings.TrimSpace(number)
		value := strings.TrimSpace(vendor)
		if key == "" || value == "" {
			continue
		}
		clean[key] = value
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("SNMP OID table contains no usable entries")
	}
	table.Entries = clean
	if strings.TrimSpace(table.Prefix) == "" {
		table.Prefix = "1.3.6.1.4.1"
	}
	return &table, nil
}

// SetSNMPOIDTable swaps the process-wide table, mainly for bundles and tests.
func SetSNMPOIDTable(table *SNMPOIDTable) {
	if table == nil {
		return
	}
	snmpOIDState.Lock()
	snmpOIDState.table = table
	snmpOIDState.Unlock()
}

// SNMPOIDVersion reports the loaded table version.
func SNMPOIDVersion() string {
	snmpOIDState.RLock()
	defer snmpOIDState.RUnlock()
	if snmpOIDState.table == nil {
		return ""
	}
	return snmpOIDState.table.Version
}

// LookupSNMPVendor resolves a sysObjectID such as "1.3.6.1.4.1.2011.2.23" to
// the registering organisation. Bare enterprise numbers ("2011") also work.
func LookupSNMPVendor(oid string) (string, float64, bool) {
	number := enterpriseNumber(oid)
	if number == "" {
		return "", 0, false
	}
	snmpOIDState.RLock()
	table := snmpOIDState.table
	snmpOIDState.RUnlock()
	if table == nil {
		return "", 0, false
	}
	vendor, ok := table.Entries[number]
	if !ok || vendor == "" {
		return "", 0, false
	}
	return vendor, SNMPVendorConfidence, true
}

// enterpriseNumber extracts the private enterprise number from an OID. Only the
// documented prefix is accepted; arbitrary numeric strings would otherwise make
// any sysObjectID resolve to an unrelated vendor.
func enterpriseNumber(oid string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(oid), ".")
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) == 1 {
		for _, r := range parts[0] {
			if r < '0' || r > '9' {
				return ""
			}
		}
		return parts[0]
	}
	if len(parts) < 7 {
		return ""
	}
	if strings.Join(parts[:6], ".") != "1.3.6.1.4.1" {
		return ""
	}
	return parts[6]
}

func mustLoadSNMPOIDTable(data []byte) *SNMPOIDTable {
	table, err := ParseSNMPOIDTable(data)
	if err != nil {
		panic(err)
	}
	return table
}
