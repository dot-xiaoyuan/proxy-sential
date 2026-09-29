package store

import "testing"

func TestRetentionCandidateByteBudget(t *testing.T) {
	for _, tt := range []struct {
		name       string
		count      int
		used, next int64
		fits       bool
	}{
		{"first small", 0, 0, 1024, true},
		{"exact budget", 1, 4 << 20, 4 << 20, true},
		{"too large combined", 1, 4 << 20, (4 << 20) + 1, false},
		{"oversized first must progress", 0, 0, 81 << 20, true},
		{"oversized must stand alone", 1, 81 << 20, 1, false},
		{"no overflow", 1, 8 << 20, 1 << 62, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := retentionCandidateFits(tt.count, tt.used, tt.next); got != tt.fits {
				t.Fatalf("fits=%v want %v", got, tt.fits)
			}
		})
	}
}
