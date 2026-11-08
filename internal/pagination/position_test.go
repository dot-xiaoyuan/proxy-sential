package pagination

import "testing"

func TestBoundaryOffset(t *testing.T) {
	for _, tc := range []struct {
		page, limit int
		want        int64
	}{{1, 20, -1}, {2, 20, 19}, {7, 50, 299}} {
		got, err := BoundaryOffset(tc.page, tc.limit)
		if err != nil || got != tc.want {
			t.Fatalf("page=%d limit=%d offset=%d err=%v", tc.page, tc.limit, got, err)
		}
	}
	for _, tc := range [][2]int{{0, 20}, {-1, 20}, {1, 0}, {1, 201}, {1000000001, 20}} {
		if _, err := BoundaryOffset(tc[0], tc[1]); err == nil {
			t.Fatalf("accepted invalid page/limit: %v", tc)
		}
	}
}
