package controlplane

import "net/http"

// Location directories are administrative metadata, like the identity bridge
// configuration. They may be maintained during read-only observation without
// enabling risk actions. Authentication, organization:write, CSRF and audit still
// apply in the normal request path. Keep this list exact, never prefix-based.
func organizationConfigurationAllowed(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	switch path {
	case "/organization/campuses", "/organization/buildings", "/organization/network-zones", "/organization/access-points":
		return true
	default:
		return false
	}
}
