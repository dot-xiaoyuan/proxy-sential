package streamlog

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

type SourceBlocker struct {
	Epoch     string    `json:"epoch"`
	SegmentID string    `json:"segment_id"`
	Stage     string    `json:"stage"`
	Reason    string    `json:"reason"`
	FirstAt   time.Time `json:"first_failed_at"`
}

func (j *Journal) SourceBlocker(source, path string) (SourceBlocker, error) {
	var blocker SourceBlocker
	data, err := os.ReadFile(j.path(sourceCursorID(source, path), ".blocker"))
	if errors.Is(err, os.ErrNotExist) {
		return blocker, nil
	}
	if err != nil {
		return blocker, err
	}
	err = json.Unmarshal(data, &blocker)
	return blocker, err
}

// A blocker is a diagnostic record, never an ACK or cursor change.
func (j *Journal) RecordSourceBlocker(source, path string, blocker SourceBlocker) error {
	return atomicJSON(j.path(sourceCursorID(source, path), ".blocker"), blocker)
}

type PendingSourceSegment struct {
	AcceptedAt time.Time
	Bytes      int64
	Archived   bool
}

func (j *Journal) PendingSourceSegment(id string) (PendingSourceSegment, error) {
	state, err := j.loadPendingStatus(id)
	if err != nil {
		return PendingSourceSegment{}, err
	}
	info, err := os.Stat(j.path(id, ".segment"))
	if err != nil {
		return PendingSourceSegment{}, err
	}
	return PendingSourceSegment{AcceptedAt: state.Segment.AcceptedAt, Bytes: info.Size(), Archived: state.Acks[Archive] == Acked}, nil
}
