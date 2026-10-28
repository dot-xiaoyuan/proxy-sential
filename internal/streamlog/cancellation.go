package streamlog

import (
	"errors"
	"fmt"
	"time"
)

// CancellationSegment is a compact audit of remaining sink work. It never
// contains event bodies and never changes a cursor or acknowledgement.
type CancellationSegment struct {
	ID            string          `json:"segment_id"`
	ContentSHA256 string          `json:"content_sha256"`
	FileID        string          `json:"file_id"`
	StartOffset   int64           `json:"start_offset"`
	EndOffset     int64           `json:"end_offset"`
	Events        int             `json:"events"`
	AcceptedAt    time.Time       `json:"accepted_at"`
	Acks          map[Lane]Status `json:"acks"`
}

// SnapshotCancellation must be called while holding the source lease. The
// original journal is retained in place; only a separate audited epoch can
// resume capture. Unread source bytes are outside this snapshot and must pass
// the existing fresh-source preparation audit before a new reader can start.
func (j *Journal) SnapshotCancellation(source, path string, cutoff time.Time) (SourceCursor, []CancellationSegment, error) {
	if cutoff.IsZero() || cutoff.After(time.Now()) {
		return SourceCursor{}, nil, errors.New("invalid cancellation cutoff")
	}
	cursor, err := j.LoadSource(source, path)
	if err != nil {
		return SourceCursor{}, nil, err
	}
	ids, err := j.PendingSegments()
	if err != nil {
		return SourceCursor{}, nil, err
	}
	if len(ids) > 500 {
		return SourceCursor{}, nil, errors.New("journal cancellation exceeds 500-segment audit bound")
	}
	items := make([]CancellationSegment, 0, len(ids))
	for _, id := range ids {
		state, err := j.load(id) // Do not rehydrate source-backed raw bytes.
		if err != nil {
			return SourceCursor{}, nil, err
		}
		s := state.Segment
		if s.Source != source || s.SourcePath != path || s.Epoch != cursor.Epoch || s.AcceptedAt.IsZero() || s.AcceptedAt.After(cutoff) || !state.Committed || s.Quarantined {
			return SourceCursor{}, nil, fmt.Errorf("segment %s is outside the stopped cancellation scope: %w", id, ErrContentConflict)
		}
		// This command cancels unfinished processing, never the only original.
		// Requiring a confirmed archive avoids losing source-backed recovery
		// when a producer later rotates its files.
		if state.Acks[Archive] != Acked && state.Acks[Archive] != NotApplicable {
			return SourceCursor{}, nil, fmt.Errorf("segment %s archive must be confirmed before cancellation: %w", id, ErrUnconfirmed)
		}
		for _, lane := range requiredLanes(s) {
			status := state.Acks[lane]
			if status != Pending && status != Attempted && status != Acked && status != NotApplicable {
				return SourceCursor{}, nil, ErrContentConflict
			}
		}
		items = append(items, CancellationSegment{ID: id, ContentSHA256: state.ContentSHA256, FileID: s.FileID,
			StartOffset: s.StartOffset, EndOffset: s.EndOffset, Events: len(s.Events), AcceptedAt: s.AcceptedAt, Acks: state.Acks})
	}
	return cursor, items, nil
}
