package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

type readyScanTimeoutError struct{}

func (readyScanTimeoutError) Error() string    { return "database statement timeout" }
func (readyScanTimeoutError) SQLState() string { return "57014" }

func TestIdentityDerivedReadyScanBudgetAdaptsWithoutSkipping(t *testing.T) {
	cases := []struct {
		name    string
		current int
		page    identityDerivedReadyPage
		err     error
		elapsed time.Duration
		want    int
	}{
		{"timeout shrinks", 256, identityDerivedReadyPage{}, context.DeadlineExceeded, 2 * time.Second, 128},
		{"database timeout shrinks", 32, identityDerivedReadyPage{}, readyScanTimeoutError{}, 2 * time.Second, 16},
		{"floor remains", 16, identityDerivedReadyPage{}, context.DeadlineExceeded, 2 * time.Second, 16},
		{"other error does not conceal fault", 128, identityDerivedReadyPage{}, errors.New("bad schema"), time.Millisecond, 128},
		{"slow success conserves IO", 128, identityDerivedReadyPage{Scanned: 128}, nil, 1500 * time.Millisecond, 64},
		{"fast full page grows", 128, identityDerivedReadyPage{Scanned: 128}, nil, 100 * time.Millisecond, 160},
		{"partial page stays", 128, identityDerivedReadyPage{Scanned: 2}, nil, 100 * time.Millisecond, 128},
		{"shared throttle stays", 128, identityDerivedReadyPage{Deferred: true}, nil, 100 * time.Millisecond, 128},
		{"ceiling remains", 256, identityDerivedReadyPage{Scanned: 256}, nil, 100 * time.Millisecond, 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextIdentityDerivedReadyScanLimit(tc.current, tc.page, tc.err, tc.elapsed); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}
