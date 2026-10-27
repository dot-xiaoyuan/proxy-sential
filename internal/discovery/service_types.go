package discovery

import "proxy-sentinel/internal/fingerprint"

// Service type definitions live with the verified offline fingerprint bundle.
// Discovery keeps these adapters so its existing callers retain their API.
type ServiceTypeEntry = fingerprint.ServiceTypeEntry
type ServiceTypeCatalog = fingerprint.ServiceTypeCatalog

var embeddedServiceTypes = fingerprint.EmbeddedServiceTypeCatalog()

func ParseServiceTypeCatalog(data []byte) (*ServiceTypeCatalog, error) {
	return fingerprint.ParseServiceTypeCatalog(data)
}

func SetServiceTypeCatalog(catalog *ServiceTypeCatalog) {
	fingerprint.SetServiceTypeCatalog(catalog)
}

func ServiceCapabilities(serviceType string) ([]string, bool) {
	return fingerprint.ServiceCapabilities(serviceType)
}

func ServiceProductKind(serviceType string) (string, bool) {
	return fingerprint.ServiceProductKind(serviceType)
}
