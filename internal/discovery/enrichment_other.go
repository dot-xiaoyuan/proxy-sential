//go:build !linux

package discovery

func verifyEnrichmentPath(Observation, EnrichmentPath) bool { return false }
