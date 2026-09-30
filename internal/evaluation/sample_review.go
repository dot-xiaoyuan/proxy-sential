package evaluation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/store"
)

// SampleID identifies the historical observation, independently of its review.
func SampleID(sample Sample) string {
	kind, id := strings.ToLower(strings.TrimSpace(sample.SubjectType)), strings.TrimSpace(sample.SubjectID)
	if id == "" {
		kind, id = "ip", sample.IP
	}
	stamp := sample.SnapshotTime
	if t, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
		stamp = t.UTC().Format(time.RFC3339Nano)
	}
	seed, _ := json.Marshal([]string{sample.Date, sample.SourceRunID, kind, id, stamp})
	sum := sha256.Sum256(seed)
	return "sample-" + hex.EncodeToString(sum[:])
}

// ApplySampleReview is shared by the live list and offline evaluation. Legacy
// run labels must identify exactly one observation through their evidence.
func ApplySampleReview(sample *Sample, peers []Sample, labels []store.Label) {
	sample.SampleID = SampleID(*sample)
	sample.ReviewStatus, sample.ReviewReason, sample.ReviewedBy, sample.ReviewedAt = "unreviewed", "", "", ""
	sample.ReviewConflict = false
	ordered := append([]store.Label(nil), labels...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, ae := time.Parse(time.RFC3339Nano, ordered[i].CreatedAt)
		b, be := time.Parse(time.RFC3339Nano, ordered[j].CreatedAt)
		if ae == nil && be == nil {
			return a.After(b)
		}
		return ordered[i].CreatedAt > ordered[j].CreatedAt
	})
	for _, label := range ordered {
		kind, target := strings.ToLower(strings.TrimSpace(label.TargetType)), strings.TrimSpace(label.TargetID)
		match := kind == "risk_snapshot" && target == sample.SampleID
		if kind == "risk_snapshot" && target == sample.SourceRunID && evidenceIDsOverlap(sample.EvidenceIDs, label.EvidenceIDs) {
			count := 0
			for _, peer := range peers {
				if peer.SourceRunID == sample.SourceRunID && evidenceIDsOverlap(peer.EvidenceIDs, label.EvidenceIDs) {
					count++
				}
			}
			if count != 1 {
				sample.ReviewConflict = true
				return
			}
			match = true
		}
		if kind != "risk_snapshot" && evidenceIDsOverlap(sample.EvidenceIDs, label.EvidenceIDs) {
			match = (kind == sample.SubjectType && target == sample.SubjectID) || (kind == "ip" && target == sample.IP) || (kind == "account" && target != "" && target == sample.AccountID) || (kind == "endpoint" && target != "" && target == sample.EndpointID)
		}
		if !match {
			continue
		}
		sample.ReviewStatus, sample.ReviewReason, sample.ReviewedBy, sample.ReviewedAt = label.Label, label.Reason, label.CreatedBy, label.CreatedAt
		sample.ReviewConflict = false
		return
	}
}
