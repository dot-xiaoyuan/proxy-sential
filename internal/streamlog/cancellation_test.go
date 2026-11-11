package streamlog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestCancellationAllowsUnarchivedInlineOriginalWithVerifiedHash(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := testSegment()
	s.AcceptedAt = time.Now().UTC().Add(-time.Minute)
	s.Raw = []byte("original source bytes")
	sum := sha256.Sum256(s.Raw)
	s.RawSHA256 = hex.EncodeToString(sum[:])
	id := appendCommitted(t, j, s)
	if err := j.BeginAttempt(id, Archive); err != nil {
		t.Fatal(err)
	}
	_, items, err := j.SnapshotCancellation(s.Source, s.SourcePath, time.Now().UTC())
	if err != nil || len(items) != 1 || items[0].Acks[Archive] != Attempted {
		t.Fatalf("verified inline original: %+v %v", items, err)
	}
}

func TestCancellationSnapshotPreservesPendingWorkAndUsesAckLog(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := testSegment()
	s.AcceptedAt = time.Now().UTC().Add(-time.Minute)
	id := appendCommitted(t, j, s)
	cutoff := time.Now().UTC()
	if _, _, err := j.SnapshotCancellation(s.Source, s.SourcePath, cutoff); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("unarchived original may be cancelled: %v", err)
	}
	if err := j.Ack(id, Archive); err != nil {
		t.Fatal(err)
	}
	if err := j.BeginAttempt(id, Search); err != nil {
		t.Fatal(err)
	}
	before, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	cursor, items, err := j.SnapshotCancellation(s.Source, s.SourcePath, cutoff)
	if err != nil || len(items) != 1 || items[0].ID != id || items[0].Acks[Search] != Attempted || items[0].Acks[Archive] != Acked {
		t.Fatalf("audit did not overlay acknowledgements: %+v %v", items, err)
	}
	after, err := j.Load(id)
	if err != nil || !reflect.DeepEqual(before, after) || cursor.Offset != s.EndOffset {
		t.Fatalf("audit changed pending work: %+v %v", after, err)
	}
	if _, _, err := j.SnapshotCancellation(s.Source, s.SourcePath, s.AcceptedAt.Add(-time.Second)); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("post-cutoff event cancelled: %v", err)
	}
	if _, _, err := j.SnapshotCancellation("another-source", s.SourcePath, cutoff); err == nil {
		t.Fatal("another source entered the cancellation scope")
	}
}
