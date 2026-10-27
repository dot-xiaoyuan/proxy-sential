package discovery

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed data/service-type-catalog.json
var embeddedServiceTypes []byte

// ServiceTypeEntry describes what an mDNS/DNS-SD service type proves about a
// device. Service announcements are capability evidence, never a whole-device
// classification on their own.
type ServiceTypeEntry struct {
	Capabilities []string `json:"capabilities"`
	ProductKind  string   `json:"product_kind"`
}

// ServiceTypeCatalog maps advertised service types to capabilities.
type ServiceTypeCatalog struct {
	Version   string                      `json:"version"`
	Source    string                      `json:"source"`
	SourceURL string                      `json:"source_url"`
	License   string                      `json:"license"`
	Entries   map[string]ServiceTypeEntry `json:"entries"`
}

var serviceTypeState = struct {
	sync.RWMutex
	catalog *ServiceTypeCatalog
}{catalog: mustLoadServiceTypes(embeddedServiceTypes)}

// ParseServiceTypeCatalog validates a service type catalogue.
func ParseServiceTypeCatalog(data []byte) (*ServiceTypeCatalog, error) {
	var catalog ServiceTypeCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode service type catalogue: %w", err)
	}
	if strings.TrimSpace(catalog.Version) == "" || strings.TrimSpace(catalog.Source) == "" {
		return nil, fmt.Errorf("service type catalogue requires a version and source")
	}
	clean := make(map[string]ServiceTypeEntry, len(catalog.Entries))
	for name, entry := range catalog.Entries {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" || !strings.HasPrefix(key, "_") {
			return nil, fmt.Errorf("service type %q is invalid", name)
		}
		clean[key] = ServiceTypeEntry{Capabilities: entry.Capabilities, ProductKind: strings.TrimSpace(entry.ProductKind)}
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("service type catalogue contains no entries")
	}
	catalog.Entries = clean
	return &catalog, nil
}

// SetServiceTypeCatalog swaps the process-wide catalogue, mainly for tests.
func SetServiceTypeCatalog(catalog *ServiceTypeCatalog) {
	if catalog == nil {
		return
	}
	serviceTypeState.Lock()
	serviceTypeState.catalog = catalog
	serviceTypeState.Unlock()
}

// ServiceCapabilities returns the capabilities an advertised service implies.
func ServiceCapabilities(serviceType string) ([]string, bool) {
	key := strings.ToLower(strings.TrimSpace(serviceType))
	if key == "" {
		return nil, false
	}
	serviceTypeState.RLock()
	catalog := serviceTypeState.catalog
	serviceTypeState.RUnlock()
	if catalog == nil {
		return nil, false
	}
	entry, ok := catalog.Entries[key]
	if !ok {
		return nil, false
	}
	return entry.Capabilities, true
}

// ServiceProductKind returns the product line an advertised service implies.
func ServiceProductKind(serviceType string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(serviceType))
	serviceTypeState.RLock()
	catalog := serviceTypeState.catalog
	serviceTypeState.RUnlock()
	if catalog == nil {
		return "", false
	}
	entry, ok := catalog.Entries[key]
	if !ok || entry.ProductKind == "" {
		return "", false
	}
	return entry.ProductKind, true
}

func mustLoadServiceTypes(data []byte) *ServiceTypeCatalog {
	catalog, err := ParseServiceTypeCatalog(data)
	if err != nil {
		panic(err)
	}
	return catalog
}
