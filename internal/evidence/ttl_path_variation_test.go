package evidence

import (
	"strings"
	"testing"
)

func TestTTLPathVariationIsNotHostDiversity(t *testing.T) {
	for _, tc := range []struct {
		name          string
		left, right   int
		direction     string
		wantDiversity bool
	}{
		{"one_hop", 63, 64, "unknown", false},
		{"two_hops", 62, 64, "unknown", false},
		{"same_128_family", 126, 127, "unknown", false},
		{"different_direction", 63, 126, "inbound", false},
		{"distinct_initial_families", 63, 126, "unknown", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := normalizedLine("left", "device", map[string]any{"ttl": tc.left}, map[string]any{"direction": "unknown", "traffic_scope": "unicast"}) + "\n" + normalizedLine("right", "device", map[string]any{"ttl": tc.right}, map[string]any{"direction": tc.direction, "traffic_scope": "unicast"}) + "\n"
			result, err := Analyze(strings.NewReader(input), Options{})
			if err != nil {
				t.Fatal(err)
			}
			found, variation := false, false
			for _, item := range result.Evidence {
				if item.Type == "ttl_clusters" {
					found = true
				}
				if item.Type == "ttl_path_variation" {
					variation = true
					if item.Score != 0 || len(item.Samples) != 2 || item.Reason == "" {
						t.Fatal("path variation was scored or lost explanation", item)
					}
				}
			}
			if found != tc.wantDiversity {
				t.Errorf("host diversity=%v want=%v", found, tc.wantDiversity)
			}
			if !tc.wantDiversity && tc.direction == "unknown" && !variation {
				t.Error("unscored path variation explanation missing")
			}
		})
	}
}
