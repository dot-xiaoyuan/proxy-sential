package streamlog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestProjectionPolicyLegacyFingerprint(t *testing.T) {
	segment := testSegment()
	hash, err := contentHash(segment)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "f2afa15040acc4986ded90769ad92fbfec97e626a04b0a06a26fba5b3673da6e" ||
		SourceSegmentID(segment) != "bed727cd6a93bc7a8e8f1767c810bda5af127282f66852d75ec721f8d9625757" {
		t.Fatalf("legacy source fingerprint changed: hash=%s id=%s", hash, SourceSegmentID(segment))
	}
	encoded, err := json.Marshal(segment)
	if err != nil || strings.Contains(string(encoded), "projection_responsibility") {
		t.Fatalf("legacy segment gained policy bytes: %s %v", encoded, err)
	}
	explicit := segment
	explicit.ProjectionPolicy = ProjectionPolicyFull
	explicitHash, err := contentHash(explicit)
	if err != nil || explicitHash == hash || SourceSegmentID(explicit) != SourceSegmentID(segment) {
		t.Fatalf("explicit policy must bind content, not change source identity: %s %v", explicitHash, err)
	}
}

func TestProjectionPolicyCannotChangeCommittedSourceInterval(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	segment := testSegment()
	segment.Source, segment.SourcePath, segment.ParserVersion = "passive-discovery", "packet://bond0/sensor", "passive-frame-v1"
	if _, err := j.Append(segment); err != nil {
		t.Fatal(err)
	}
	segment.ProjectionPolicy = ProjectionPolicyFull
	if _, err := j.Append(segment); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("same interval accepted a changed policy: %v", err)
	}
	segment.ProjectionPolicy = "unknown"
	segment.StartOffset, segment.EndOffset = 42, 72
	if _, err := j.Append(segment); !errors.Is(err, ErrContentConflict) {
		t.Fatalf("unknown projection responsibility accepted: %v", err)
	}
}
