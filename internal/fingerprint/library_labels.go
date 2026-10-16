package fingerprint

import (
	"sort"
	"strings"
)

// RouterLibraryLabel is one open-source library's contribution to a router assessment.
// A library is shown as a label whenever it recognises part of a device; only libraries
// whose license allows it to be a role basis may score or name a role.
type RouterLibraryLabel struct {
	ID           string
	License      string
	RoleEligible bool
}

// LibraryRoleEligible reports whether a catalog source may act as a router role basis.
// Copyleft (GPL/LGPL) sources are kept for internal display only: their rules may label a
// device but never score a router, name its role, or count as an independent source.
func LibraryRoleEligible(license string) bool {
	upper := strings.ToUpper(license)
	return !strings.Contains(upper, "GPL")
}

// SourceLicense returns the license recorded for a catalog source ID.
func (c *Catalog) SourceLicense(sourceID string) string {
	if c == nil {
		return ""
	}
	for _, source := range c.Sources {
		if source.ID == sourceID {
			return source.License
		}
	}
	return ""
}

// routerCatalogFields maps router evidence inputs (see evidence.routerInputs) to the
// catalog's standard fields. Only inputs that the router pipeline actually produces are
// listed; a catalog field without a producer here would be a silent dead mapping.
var routerCatalogFields = map[string]string{
	"hostname":          "hostname",
	"vendor_class":      "dhcp_vendor_class",
	"requested_options": "dhcp_requested_options",
	"user_agent":        "user_agent",
	"http_server":       "http_server",
	"http_title":        "http_title",
	"tls_subject":       "tls_subject",
	"tls_issuer":        "tls_issuer",
	"tls_san":           "tls_san",
	"snmp_sysdescr":     "snmp_sysdescr",
}

// RouterCatalogValues converts router evidence inputs into catalog match values.
func RouterCatalogValues(inputs map[string][]string) map[string][]string {
	values := map[string][]string{}
	for input, field := range routerCatalogFields {
		for _, value := range inputs[input] {
			if strings.TrimSpace(value) != "" {
				values[field] = append(values[field], value)
			}
		}
	}
	return values
}

// LibraryDisplayName is the name shown for a catalog source on router labels.
// LibrarySourceIDs returns the distinct open-source library IDs that matched a device,
// sorted for a stable order. Matches are labels for display; they never change a score.
func LibrarySourceIDs(matches []SourceMatch) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, match := range matches {
		if match.SourceID == "" || seen[match.SourceID] {
			continue
		}
		seen[match.SourceID] = true
		out = append(out, match.SourceID)
	}
	sort.Strings(out)
	return out
}

func LibraryDisplayName(sourceID string) string {
	names := map[string]string{"recog": "Recog", "satori": "Satori", "whatweb": "WhatWeb", "librenms": "LibreNMS", "openwrt": "OpenWrt ToH", "fingerbank-current": "Fingerbank", "p0f": "p0f"}
	if name, ok := names[sourceID]; ok {
		return name
	}
	return sourceID
}
