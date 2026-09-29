package controlplane

import (
	"fmt"
	"net"
	"proxy-sentinel/internal/policy"
)

// Test exceptions are startup-only private configuration, never HTTP input.
func ValidateNativeTestListener(runtimes map[string]NativeActionRuntime, addr string) error {
	for _, r := range runtimes {
		if r.TestAccount == "" {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("native test account requires an explicit loopback listener")
		}
	}
	return nil
}
func (s *Server) nativeTestAccountAllowed(connector, account, campus, domain string) bool {
	r, ok := s.nativeActions[connector]
	return ok && r.TestAccount != "" && r.TestAccount == account && r.CampusID == campus && r.AccessDomain == domain
}
func (s *Server) nativeTestStageAllowed(e policy.Execution, index int) bool {
	if e.Definition.Mode != "manual" || e.Definition.Trigger != "shared_access" || index >= len(e.Definition.Stages) {
		return false
	}
	st := e.Definition.Stages[index]
	r := s.nativeActions[st.ConnectorID]
	return st.Action == "disconnect" && s.nativeTestAccountAllowed(st.ConnectorID, e.AccountID, r.CampusID, r.AccessDomain)
}
