package controlplane

import (
	"net/http"
	"testing"
)

func Test4KDatabasePermissionRequiresIntegrationWrite(t *testing.T) {
	for _, prefix := range []string{"", "/api/v1"} {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPost} {
			if got := requiredPermission(method, prefix+"/actions/connectors/test/4k-database"); got != "integrations:write" {
				t.Fatalf("%s %s: %s", method, prefix, got)
			}
		}
	}
}
