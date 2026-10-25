package materialize

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/store"
)

// IncrementalStore keeps the bounded feature read separate from the atomic
// PostgreSQL result-and-generation commit. A claim is never acknowledged by
// this runner before its selected facts are committed.
type IncrementalStore interface {
	StreamRiskFreshCutoff(context.Context, string) (time.Time, error)
	QueueExpiredStreamRiskSubjects(context.Context, string, time.Time, int) error
	ClaimRiskSubjects(context.Context, string, int) ([]store.RiskSubjectClaim, error)
	ListStreamRiskFeatureEvents(context.Context, string, []store.RiskSubjectClaim, time.Time, time.Time, time.Time, int) ([]normalized.Event, error)
	ApplyStreamRiskEvaluation(context.Context, string, []store.RiskSubjectClaim, []evidence.Evidence, []risk.Snapshot, time.Time) error
	ReleaseRiskSubjects(context.Context, []store.RiskSubjectClaim) error
}

type IncrementalOptions struct {
	SensorID     string
	AsOf         time.Time
	Window       time.Duration
	ClaimLimit   int
	FeatureLimit int
}

type IncrementalResult struct {
	Claims         int
	Features       int
	Evidence       int
	Snapshots      int
	OldestClaimAge time.Duration
}

func RunIncrementalOnce(ctx context.Context, backend IncrementalStore, opts IncrementalOptions) (result IncrementalResult, err error) {
	if backend == nil || opts.SensorID == "" {
		return IncrementalResult{}, errors.New("incremental risk needs a sensor and storage owner")
	}
	if opts.AsOf.IsZero() {
		opts.AsOf = time.Now().UTC()
	}
	if opts.Window == 0 {
		opts.Window = 10 * time.Minute
	}
	if opts.ClaimLimit == 0 {
		opts.ClaimLimit = 64
	}
	if opts.FeatureLimit == 0 {
		opts.FeatureLimit = 20000
	}
	if opts.Window <= 0 || opts.Window > 7*24*time.Hour || opts.ClaimLimit < 1 || opts.ClaimLimit > 256 || opts.FeatureLimit < 1 || opts.FeatureLimit > 20000 {
		return IncrementalResult{}, errors.New("incremental risk bounds are invalid")
	}
	freshCutoff, err := backend.StreamRiskFreshCutoff(ctx, opts.SensorID)
	if err != nil {
		return IncrementalResult{}, fmt.Errorf("load risk fresh cutoff: %w", err)
	}
	if freshCutoff.IsZero() || freshCutoff.After(opts.AsOf) {
		return IncrementalResult{}, errors.New("incremental risk requires an audited fresh cutoff")
	}
	if err := backend.QueueExpiredStreamRiskSubjects(ctx, opts.SensorID, opts.AsOf.Add(-opts.Window), opts.ClaimLimit); err != nil {
		return IncrementalResult{}, fmt.Errorf("queue expired risk subjects: %w", err)
	}
	claims, err := backend.ClaimRiskSubjects(ctx, opts.SensorID, opts.ClaimLimit)
	if err != nil || len(claims) == 0 {
		return IncrementalResult{}, err
	}
	result = IncrementalResult{Claims: len(claims)}
	claimedAt := time.Now().UTC()
	for _, claim := range claims {
		if !claim.FirstDirty.IsZero() && claimedAt.After(claim.FirstDirty) && claimedAt.Sub(claim.FirstDirty) > result.OldestClaimAge {
			result.OldestClaimAge = claimedAt.Sub(claim.FirstDirty)
		}
	}
	committed := false
	defer func() {
		if !committed {
			releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if releaseErr := backend.ReleaseRiskSubjects(releaseCtx, claims); releaseErr != nil {
				err = errors.Join(err, fmt.Errorf("release risk claims: %w", releaseErr))
			}
		}
	}()
	selected := make(map[string]bool, len(claims))
	for _, claim := range claims {
		if claim.SensorID != opts.SensorID || claim.ID == "" || (claim.Type != "ip" && claim.Type != "account") {
			return result, errors.New("invalid incremental risk claim")
		}
		key := claim.Type + "\x00" + claim.ID
		if selected[key] {
			return result, errors.New("duplicate incremental risk claim")
		}
		selected[key] = true
	}
	features, err := backend.ListStreamRiskFeatureEvents(ctx, opts.SensorID, claims, opts.AsOf.Add(-opts.Window), opts.AsOf, freshCutoff, opts.FeatureLimit)
	if err != nil {
		return result, fmt.Errorf("read affected risk features: %w", err)
	}
	result.Features = len(features)
	var lines bytes.Buffer
	encoder := json.NewEncoder(&lines)
	for _, event := range features {
		if err := encoder.Encode(event); err != nil {
			return result, err
		}
	}
	analyzed, err := evidence.Analyze(&lines, evidence.Options{Window: opts.Window, AsOf: opts.AsOf})
	if err != nil {
		return result, fmt.Errorf("analyze affected risk features: %w", err)
	}
	kept := make([]evidence.Evidence, 0, len(analyzed.Evidence))
	seenEvidence := make(map[string]bool, len(analyzed.Evidence))
	for _, item := range analyzed.Evidence {
		if !selected[riskEvidenceClaimKey(item)] {
			continue
		}
		// This is a current rule interpretation for a subject/window. Repeated
		// observations update it without creating a new full evidence document.
		// The authoritative source events remain addressable by their own keys.
		fingerprint := sha256.Sum256([]byte(opts.SensorID + "\x00" + riskEvidenceClaimKey(item) + "\x00" + item.Type + "\x00" + item.Window))
		item.EvidenceID = "stream-" + hex.EncodeToString(fingerprint[:16])
		if seenEvidence[item.EvidenceID] {
			return result, errors.New("multiple risk interpretations share a stable evidence key")
		}
		seenEvidence[item.EvidenceID] = true
		kept = append(kept, item)
	}
	result.Evidence = len(kept)
	encoded, err := json.Marshal(evidence.Result{Evidence: kept})
	if err != nil {
		return result, err
	}
	scored, err := risk.Batch(bytes.NewReader(encoded))
	if err != nil {
		return result, fmt.Errorf("score affected risk evidence: %w", err)
	}
	for _, snapshot := range scored.Snapshots {
		if !selected[riskSnapshotClaimKey(snapshot)] {
			return result, errors.New("risk scorer emitted an unclaimed subject")
		}
	}
	result.Snapshots = len(scored.Snapshots)
	if err := backend.ApplyStreamRiskEvaluation(ctx, opts.SensorID, claims, kept, scored.Snapshots, opts.AsOf); err != nil {
		return result, fmt.Errorf("commit affected risk facts: %w", err)
	}
	committed = true
	return result, nil
}

func riskEvidenceClaimKey(item evidence.Evidence) string {
	if item.SubjectType == "" || item.SubjectType == "ip" {
		return "ip\x00" + item.IP
	}
	return item.SubjectType + "\x00" + item.SubjectID
}

func riskSnapshotClaimKey(item risk.Snapshot) string {
	if item.SubjectType == "" || item.SubjectType == "ip" {
		return "ip\x00" + item.IP
	}
	return item.SubjectType + "\x00" + item.SubjectID
}
