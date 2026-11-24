package materialize

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	StreamRiskFeatureEvents(context.Context, string, []store.RiskSubjectClaim, time.Time, time.Time, time.Time, int, func(normalized.Event) error) (int, error)
	ApplyStreamRiskEvaluation(context.Context, string, []store.RiskSubjectClaim, []evidence.Evidence, []risk.Snapshot, time.Time) (int, error)
	ReleaseRiskSubjects(context.Context, []store.RiskSubjectClaim) error
}

type IncrementalOptions struct {
	SensorID     string
	AsOf         time.Time
	Window       time.Duration
	ClaimLimit   int
	FeatureLimit int
	SkipExpiry   bool
	Drain        bool
}

type IncrementalResult struct {
	Claims         int
	FullBatch      bool
	Features       int
	Evidence       int
	Snapshots      int
	Committed      int
	Retried        int
	OldestClaimAge time.Duration
	ClaimElapsed   time.Duration
	FeatureElapsed time.Duration
	ScoreElapsed   time.Duration
	ApplyElapsed   time.Duration
}

func RunIncrementalOnce(ctx context.Context, backend IncrementalStore, opts IncrementalOptions) (result IncrementalResult, err error) {
	if backend == nil || opts.SensorID == "" {
		return IncrementalResult{}, errors.New("incremental risk needs a sensor and storage owner")
	}
	liveAsOf := opts.AsOf.IsZero()
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
	if opts.Window <= 0 || opts.Window > store.MaxStreamRiskWindow || opts.ClaimLimit < 1 || opts.ClaimLimit > 256 || opts.FeatureLimit < 1 || opts.FeatureLimit > 20000 {
		return IncrementalResult{}, errors.New("incremental risk bounds are invalid")
	}
	freshCutoff, err := backend.StreamRiskFreshCutoff(ctx, opts.SensorID)
	if err != nil {
		return IncrementalResult{}, fmt.Errorf("load risk fresh cutoff: %w", err)
	}
	if freshCutoff.IsZero() || freshCutoff.After(opts.AsOf) {
		return IncrementalResult{}, errors.New("incremental risk requires an audited fresh cutoff")
	}
	// A worker that just committed a full batch within its scheduling budget
	// can spread the claim, read and commit cost over more subjects. The same
	// feature byte limit and caller deadline apply in both modes.
	maxClaimsPerLease := 8
	if opts.Drain {
		maxClaimsPerLease = 24
	}
	claimLimit := min(opts.ClaimLimit, maxClaimsPerLease)
	if !opts.SkipExpiry {
		if err := backend.QueueExpiredStreamRiskSubjects(ctx, opts.SensorID, opts.AsOf.Add(-opts.Window), claimLimit); err != nil {
			return IncrementalResult{}, fmt.Errorf("queue expired risk subjects: %w", err)
		}
	}
	claimStarted := time.Now()
	claims, err := backend.ClaimRiskSubjects(ctx, opts.SensorID, claimLimit)
	result.ClaimElapsed = time.Since(claimStarted)
	if err != nil || len(claims) == 0 {
		return IncrementalResult{}, err
	}
	result.Claims = len(claims)
	result.FullBatch = len(claims) == claimLimit
	claimedAt := time.Now().UTC()
	// In live mode the snapshot must be no earlier than the PG claim. A source
	// feature accepted before its dirty generation was claimed must be inside
	// the accepted-time fence; later generations are rejected at apply time.
	if liveAsOf {
		opts.AsOf = claimedAt
	}
	for _, claim := range claims {
		firstDirty := claim.FirstDirty
		if firstDirty.Before(freshCutoff) {
			firstDirty = freshCutoff
		}
		if !firstDirty.IsZero() && claimedAt.After(firstDirty) && claimedAt.Sub(firstDirty) > result.OldestClaimAge {
			result.OldestClaimAge = claimedAt.Sub(firstDirty)
		}
	}
	skipRelease := make(map[string]bool, len(claims))
	defer func() {
		pending := make([]store.RiskSubjectClaim, 0, len(claims)-len(skipRelease))
		for _, claim := range claims {
			if !skipRelease[claim.Type+"\x00"+claim.ID] {
				pending = append(pending, claim)
			}
		}
		if len(pending) > 0 {
			releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if releaseErr := backend.ReleaseRiskSubjects(releaseCtx, pending); releaseErr != nil {
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
	// One read and commit is the usual path. Split only when the feature bound
	// is exceeded. Acked groups keep their receipts if a later group fails.
	groups := [][]store.RiskSubjectClaim{claims}
	var boundErr error
	for len(groups) > 0 {
		group := groups[0]
		groups = groups[1:]
		groupResult, groupErr := evaluateRiskClaimGroup(ctx, backend, opts, freshCutoff, group)
		result.FeatureElapsed += groupResult.FeatureElapsed
		result.ScoreElapsed += groupResult.ScoreElapsed
		result.ApplyElapsed += groupResult.ApplyElapsed
		if errors.Is(groupErr, store.ErrRiskFeatureStreamBound) {
			if len(group) > 1 {
				middle := len(group) / 2
				groups = append([][]store.RiskSubjectClaim{group[:middle], group[middle:]}, groups...)
				continue
			}
			// Retain the failed singleton's original lease until it expires. An
			// immediate release would put the same oversized subject at the
			// front of the next batch.
			claim := group[0]
			skipRelease[claim.Type+"\x00"+claim.ID] = true
			boundErr = errors.Join(boundErr, fmt.Errorf("risk subject %s/%s remains pending: %w", claim.Type, claim.ID, groupErr))
			continue
		}
		if groupErr != nil {
			return result, groupErr
		}
		result.Features += groupResult.Features
		result.Evidence += groupResult.Evidence
		result.Snapshots += groupResult.Snapshots
		result.Committed += groupResult.Committed
		result.Retried += groupResult.Retried
		for _, claim := range group {
			skipRelease[claim.Type+"\x00"+claim.ID] = true
		}
	}
	return result, boundErr
}

func evaluateRiskClaimGroup(ctx context.Context, backend IncrementalStore, opts IncrementalOptions, freshCutoff time.Time, claims []store.RiskSubjectClaim) (result IncrementalResult, err error) {
	selected := make(map[string]bool, len(claims))
	for _, claim := range claims {
		selected[claim.Type+"\x00"+claim.ID] = true
	}
	analyzer, err := evidence.NewFixedWindowStreamAnalyzer(evidence.Options{Window: opts.Window, AsOf: opts.AsOf})
	if err != nil {
		return result, err
	}
	blockSize := min(opts.FeatureLimit, 5000)
	featureStarted := time.Now()
	result.Features, err = backend.StreamRiskFeatureEvents(ctx, opts.SensorID, claims, opts.AsOf.Add(-opts.Window), opts.AsOf, freshCutoff, blockSize, analyzer.Add)
	result.FeatureElapsed = time.Since(featureStarted)
	if err != nil {
		return result, fmt.Errorf("read affected risk features: %w", err)
	}
	scoreStarted := time.Now()
	analyzed := analyzer.Result()
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
	scored := risk.ScoreEvidence(kept)
	for _, snapshot := range scored.Snapshots {
		if !selected[riskSnapshotClaimKey(snapshot)] {
			return result, errors.New("risk scorer emitted an unclaimed subject")
		}
	}
	result.Snapshots = len(scored.Snapshots)
	result.ScoreElapsed = time.Since(scoreStarted)
	applyStarted := time.Now()
	committedCount, err := backend.ApplyStreamRiskEvaluation(ctx, opts.SensorID, claims, kept, scored.Snapshots, opts.AsOf)
	result.ApplyElapsed = time.Since(applyStarted)
	if err != nil {
		return result, fmt.Errorf("commit affected risk facts: %w", err)
	}
	if committedCount < 0 || committedCount > len(claims) {
		return result, errors.New("invalid incremental risk commit count")
	}
	result.Committed = committedCount
	result.Retried = len(claims) - committedCount
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
