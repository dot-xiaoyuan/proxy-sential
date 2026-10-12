package discovery

import (
	"proxy-sentinel/internal/normalized"
	"testing"
)

func TestCaptureScopeKeepsOnlyAttributedPilotDevices(t *testing.T) {
	allow, err := ParseCaptureCIDRs("10.152.42.0/24")
	if err != nil {
		t.Fatal(err)
	}
	events := []normalized.Event{
		{EventID: "in", Subject: map[string]any{"ip": "10.152.42.13"}},
		{EventID: "outside", Subject: map[string]any{"ip": "10.152.43.13"}},
		{EventID: "unresolved", Subject: map[string]any{"ip": ""}},
		{EventID: "invalid", Subject: map[string]any{"ip": "bad-ip"}},
	}
	kept := filterCaptureEvents(events, allow)
	if len(kept) != 1 || kept[0].EventID != "in" {
		t.Fatalf("unexpected captured devices: %+v", kept)
	}
}

func TestCaptureScopeRequiresExplicitCIDRs(t *testing.T) {
	for _, raw := range []string{"", "0.0.0.0/0", "10.152.42.0/33"} {
		if _, err := ParseCaptureCIDRs(raw); err == nil {
			t.Fatalf("accepted unsafe capture scope %q", raw)
		}
	}
}
