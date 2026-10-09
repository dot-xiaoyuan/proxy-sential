package sharedaccess

import "testing"

func TestTTLPathFamilyDecodesOnlyExplainableInitialFamilies(t *testing.T) {
	for _, tc := range []struct {
		path, direction string
		initial         int
		valid           bool
	}{
		{"direction=outbound,initial=64,hops=1,observed=63", "outbound", 64, true},
		{"initial=128,hops=2", "unknown", 128, true},
		{"out:64:1", "outbound", 64, true}, {"in:128:2", "inbound", 128, true},
		{"63", "unknown", 64, true}, {"127", "unknown", 128, true},
		{"initial=64,initial=128", "", 0, false},
		{"direction=outbound,direction=inbound,initial=64", "", 0, false},
		{"direction=invalid,initial=64", "", 0, false},
		{"initial=63,hops=1", "", 0, false},
		{"opaque-path", "", 0, false}, {"0", "", 0, false}, {"256", "", 0, false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			direction, initial, valid := TTLPathFamily(tc.path)
			if valid != tc.valid || valid && (direction != tc.direction || initial != tc.initial) {
				t.Fatalf("family=(%s,%d,%v) want=%+v", direction, initial, valid, tc)
			}
		})
	}
}
