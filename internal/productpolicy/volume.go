package productpolicy

import (
	"strings"
	"unicode/utf8"
)

// Count escaped string bytes without allocating a second copy of a potentially
// large value. encoding/json also escapes HTML characters and U+2028/U+2029.
// Structural overhead is checked against the exact canonical JSON afterwards.
func jsonStringBytes(value string) int {
	bytes := 2
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		switch {
		case r == utf8.RuneError && size == 1, r == '\u2028', r == '\u2029', r == '<', r == '>', r == '&':
			bytes += 6
		case r == '"', r == '\\', r == '\n', r == '\r', r == '\t', r == '\b', r == '\f':
			bytes += 2
		case r < 0x20:
			bytes += 6
		default:
			bytes += size
		}
		if bytes > MaxSnapshotBytes {
			return bytes
		}
	}
	return bytes
}

func (s Snapshot) validateVolume() error {
	if len(s.Products) > 10000 || len(s.Controls) > 10000 || len(s.AntiProxyProfiles) > 10000 {
		return ErrCatalogResourceLimit
	}
	remaining, relations, referenceFields := MaxSnapshotBytes, MaxCatalogRelations, MaxCatalogReferenceFields
	add := func(values ...string) bool {
		for _, value := range values {
			bytes := jsonStringBytes(value)
			if bytes > remaining {
				return false
			}
			remaining -= bytes
		}
		return true
	}
	if len(s.ContentHash) > 64 || !add(s.SchemaVersion, s.Source, s.InstanceID) {
		return ErrCatalogResourceLimit
	}
	for _, p := range s.Products {
		if len(strings.TrimSpace(p.ID)) > 200 || len(strings.TrimSpace(p.Name)) > 500 || len(p.ControlIDs) > relations || !add(p.ID, p.Name, p.Manager) {
			return ErrCatalogResourceLimit
		}
		relations -= len(p.ControlIDs)
		for _, id := range p.ControlIDs {
			if len(strings.TrimSpace(id)) > 200 || !add(id) {
				return ErrCatalogResourceLimit
			}
		}
	}
	for _, c := range s.Controls {
		if len(strings.TrimSpace(c.ID)) > 200 || len(strings.TrimSpace(c.Name)) > 500 || len(c.Reference) > 256 || len(c.Reference) > referenceFields || !add(c.ID, c.Name) {
			return ErrCatalogResourceLimit
		}
		referenceFields -= len(c.Reference)
		for key, value := range c.Reference {
			if len(key) > 200 || len(value) > 10000 || !add(key, value) {
				return ErrCatalogResourceLimit
			}
		}
	}
	for _, p := range s.AntiProxyProfiles {
		if len(p.TargetIDs) > relations || len(p.Unsupported) > relations-len(p.TargetIDs) || !add(p.ExternalID, p.Name, p.TargetType) {
			return ErrCatalogResourceLimit
		}
		relations -= len(p.TargetIDs) + len(p.Unsupported)
		for _, values := range [][]string{p.TargetIDs, p.Unsupported} {
			for _, value := range values {
				if !add(value) {
					return ErrCatalogResourceLimit
				}
			}
		}
	}
	return nil
}
