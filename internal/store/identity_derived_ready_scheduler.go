package store

import (
	"context"
	"database/sql"
	"errors"
)

// The scheduler is owned by one worker. The old pending lane receives one of
// every four first attempts while fresh work receives three; an empty lane
// yields its slot. This bounds starvation without changing accepted_at.
type identityDerivedReadyScheduler struct {
	turn  uint8
	claim func(context.Context, int) (identityExportFragment, error)
}

func (s *identityDerivedReadyScheduler) next(ctx context.Context) (identityExportFragment, error) {
	priority := 0
	if s.turn == 3 {
		priority = 1
	}
	s.turn = (s.turn + 1) % 4
	fragment, err := s.claim(ctx, priority)
	if !errors.Is(err, sql.ErrNoRows) {
		return fragment, err
	}
	return s.claim(ctx, 1-priority)
}
