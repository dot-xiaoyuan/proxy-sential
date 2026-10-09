package store

import (
	"testing"

	"proxy-sentinel/internal/evidence"
)

func TestRouterBindingsRequireExactMACOrEndpoint(t *testing.T) {
	item := evidence.RouterAssessment{MAC: "AA:BB:CC:DD:EE:FF", EndpointID: "router-endpoint"}
	sessions := []routerAuthSession{
		{session: AccountSession{SessionID: "mac", AccountID: "mac-account", MAC: "aa-bb-cc-dd-ee-ff", IP: "10.0.0.8", Source: "ncu-srun4k"}},
		{session: AccountSession{SessionID: "endpoint", AccountID: "endpoint-account", EndpointID: "router-endpoint", IP: "2001:db8::8", Source: "ncu-srun4k"}},
		{session: AccountSession{SessionID: "private-ip", AccountID: "must-not-match", MAC: "00:11:22:33:44:55", IP: "192.168.1.1", VLAN: "10", Source: "ncu-srun4k"}},
	}
	bindings := routerBindingsForAssessment(item, sessions)
	if len(bindings) != 2 || !bindings[0].Ambiguous || !bindings[1].Ambiguous {
		t.Fatalf("expected two explicitly ambiguous exact matches, got %#v", bindings)
	}
	for _, binding := range bindings {
		if binding.AccountID == "must-not-match" {
			t.Fatal("private IP or VLAN created an unsafe identity association")
		}
	}
}

func TestRouterBindingsAggregateDualStackSession(t *testing.T) {
	item := evidence.RouterAssessment{MAC: "aa:bb:cc:dd:ee:ff"}
	base := AccountSession{SessionID: "one", AccountID: "student", MAC: "aa:bb:cc:dd:ee:ff", Source: "ncu-srun4k"}
	v4, v6 := base, base
	v4.IP, v6.IP = "10.0.0.8", "2001:db8::8"
	bindings := routerBindingsForAssessment(item, []routerAuthSession{{session: v4}, {session: v6}})
	if len(bindings) != 1 || bindings[0].Ambiguous || len(bindings[0].AssignedIPs) != 2 || bindings[0].MatchBasis != "exact_mac" {
		t.Fatalf("unexpected dual-stack aggregation: %#v", bindings)
	}
}

func TestRouterBindingsPreferExactEndpointBasis(t *testing.T) {
	item := evidence.RouterAssessment{MAC: "aa:bb:cc:dd:ee:ff", EndpointID: "endpoint-1"}
	session := AccountSession{SessionID: "one", AccountID: "student", MAC: "aa:bb:cc:dd:ee:ff", EndpointID: "endpoint-1", IP: "10.0.0.8", Source: "ncu-srun4k"}
	bindings := routerBindingsForAssessment(item, []routerAuthSession{{session: session}})
	if len(bindings) != 1 || bindings[0].MatchBasis != "exact_endpoint" {
		t.Fatalf("unexpected match basis: %#v", bindings)
	}
}
