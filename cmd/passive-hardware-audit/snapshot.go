package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/fingerprint"
)

type factSnapshotRow struct {
	Kind     string                   `json:"kind"`
	AsOf     time.Time                `json:"as_of"`
	From     time.Time                `json:"from"`
	Cohort   int                      `json:"cohort"`
	Key      string                   `json:"key"`
	Split    string                   `json:"split"`
	State    discovery.HardwareState  `json:"state"`
	Facts    []discovery.HardwareFact `json:"facts"`
	Overflow bool                     `json:"overflow"`
}

type replayCounts struct {
	Identities              int            `json:"identities"`
	Comparable              int            `json:"comparable"`
	BaselineTypes           map[string]int `json:"baseline_types"`
	CandidateTypes          map[string]int `json:"candidate_types,omitempty"`
	BaselineStatus          map[string]int `json:"baseline_status"`
	CandidateStatus         map[string]int `json:"candidate_status,omitempty"`
	BaselineModels          int            `json:"baseline_confirmed_models"`
	CandidateModels         int            `json:"candidate_confirmed_models"`
	NewlyIdentified         int            `json:"newly_identified"`
	LostIdentification      int            `json:"lost_identification"`
	ChangedTypes            int            `json:"changed_types"`
	BaselineLiveDifferences int            `json:"baseline_differs_from_live_snapshot"`
	Excluded                map[string]int `json:"excluded"`
}

type replayChange struct {
	IdentityHash string                    `json:"identity_sha256"`
	Split        string                    `json:"split"`
	Before       discovery.HardwareDetails `json:"before"`
	After        discovery.HardwareDetails `json:"after"`
}

type replayReport struct {
	InputSHA256 string                   `json:"input_sha256"`
	Snapshot    json.RawMessage          `json:"snapshot"`
	Baseline    string                   `json:"baseline_bundle"`
	Candidate   string                   `json:"candidate_bundle,omitempty"`
	Cohorts     map[string]*replayCounts `json:"cohorts"`
	Changes     []replayChange           `json:"changes"`
}

func readSnapshotCatalog(path string) (*fingerprint.HardwareCatalog, string, error) {
	bundle, err := fingerprint.VerifyBundleFile(path)
	if err != nil {
		return nil, "", err
	}
	if bundle.Manifest.SchemaVersion != fingerprint.BundleSchemaVersionV8 {
		return nil, "", fmt.Errorf("frozen hardware comparison requires a V8 bundle")
	}
	catalog, err := fingerprint.ParseHardwareCatalog(bundle.Files["hardware-catalog.json"], bundle.Files["multisource-provenance.json"], bundle.Files["hardware-provenance.json"])
	return catalog, bundle.Manifest.Version, err
}

func compareSnapshot(input io.Reader, baselinePath, candidatePath string, developmentOnly bool) (replayReport, error) {
	base, version, err := readSnapshotCatalog(baselinePath)
	if err != nil {
		return replayReport{}, fmt.Errorf("baseline: %w", err)
	}
	out := replayReport{Baseline: version, Cohorts: map[string]*replayCounts{}, Changes: []replayChange{}}
	var candidate *fingerprint.HardwareCatalog
	if candidatePath != "" {
		candidate, out.Candidate, err = readSnapshotCatalog(candidatePath)
		if err != nil {
			return out, fmt.Errorf("candidate: %w", err)
		}
	}
	const maxBytes = 64 << 20
	hash := sha256.New()
	bounded := &io.LimitedReader{R: input, N: maxBytes + 1}
	scanner := bufio.NewScanner(io.TeeReader(bounded, hash))
	scanner.Buffer(make([]byte, 64<<10), maxBytes)
	if !scanner.Scan() {
		return out, fmt.Errorf("missing snapshot header: %v", scanner.Err())
	}
	var metadata factSnapshotRow
	if err := json.Unmarshal(scanner.Bytes(), &metadata); err != nil {
		return out, fmt.Errorf("snapshot header: %w", err)
	}
	if metadata.Kind != "meta" || metadata.From.IsZero() || metadata.AsOf.Sub(metadata.From) != 24*time.Hour || metadata.Cohort < 1 || metadata.Cohort > 20000 {
		return out, fmt.Errorf("invalid frozen snapshot window or cohort")
	}
	out.Snapshot = append(json.RawMessage(nil), scanner.Bytes()...)
	seen := make(map[string]bool, metadata.Cohort)
	for scanner.Scan() {
		if len(seen) >= metadata.Cohort || bounded.N <= 0 {
			return out, fmt.Errorf("snapshot exceeds declared cohort or byte limit")
		}
		var row factSnapshotRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return out, fmt.Errorf("snapshot device row %d: %w", len(seen)+1, err)
		}
		keyHash := sha256.Sum256([]byte(row.Key))
		split := "holdout"
		if keyHash[0] < 179 {
			split = "development"
		}
		if row.Kind != "device" || row.Key == "" || row.Key != row.State.IdentityKey || row.Split != split || seen[row.Key] {
			return out, fmt.Errorf("invalid or duplicate identity in snapshot device row %d", len(seen)+1)
		}
		seen[row.Key] = true
		if developmentOnly && split == "holdout" {
			continue
		}
		counts := out.Cohorts[split]
		if counts == nil {
			counts = &replayCounts{
				BaselineTypes: map[string]int{}, CandidateTypes: map[string]int{},
				BaselineStatus: map[string]int{}, CandidateStatus: map[string]int{},
				Excluded: map[string]int{},
			}
			out.Cohorts[split] = counts
		}
		counts.Identities++
		if row.Overflow || len(row.Facts) == 0 {
			counts.Excluded["outside_replay_fact_bounds"]++
			continue
		}
		for _, fact := range row.Facts {
			if fact.IdentityKey != row.Key || !fact.ObservedAt.Before(metadata.AsOf) {
				return out, fmt.Errorf("fact outside identity or cutoff in snapshot row %d", len(seen))
			}
		}
		row.Facts = compactReplayFacts(row.Facts)
		if len(row.Facts) > 512 {
			counts.Excluded["outside_replay_fact_bounds"]++
			continue
		}
		factBytes := 0
		for _, fact := range row.Facts {
			raw, err := json.Marshal(fact)
			if err != nil {
				return out, err
			}
			factBytes += len(raw)
		}
		if factBytes > 1<<20 {
			counts.Excluded["outside_replay_byte_bounds"]++
			continue
		}
		previous := &row.State
		if row.State.TypeEvidenceAt != nil && !row.State.TypeEvidenceAt.Before(metadata.AsOf) {
			previous = nil
		}
		before, err := discovery.ReplayHardwareFacts(row.Facts, previous, metadata.AsOf, base)
		if err != nil {
			counts.Excluded["baseline_evaluation_incomplete"]++
			continue
		}
		var after discovery.HardwareState
		if candidate != nil {
			after, err = discovery.ReplayHardwareFacts(row.Facts, previous, metadata.AsOf, candidate)
			if err != nil {
				counts.Excluded["candidate_evaluation_incomplete"]++
				continue
			}
		}
		counts.Comparable++
		if !sameClassification(before.HardwareDetails, row.State.HardwareDetails) {
			counts.BaselineLiveDifferences++
		}
		counts.BaselineStatus[before.HardwareTypeStatus]++
		if before.HardwareTypeStatus == "identified" {
			counts.BaselineTypes[before.HardwareType]++
		}
		if before.HardwareModelStatus == "identified" {
			counts.BaselineModels++
		}
		if candidate == nil {
			continue
		}
		counts.CandidateStatus[after.HardwareTypeStatus]++
		if after.HardwareTypeStatus == "identified" {
			counts.CandidateTypes[after.HardwareType]++
		}
		if after.HardwareModelStatus == "identified" {
			counts.CandidateModels++
		}
		switch {
		case after.HardwareTypeStatus == "identified" && before.HardwareTypeStatus != "identified":
			counts.NewlyIdentified++
		case before.HardwareTypeStatus == "identified" && after.HardwareTypeStatus != "identified":
			counts.LostIdentification++
		case before.HardwareTypeStatus == "identified" && after.HardwareType != before.HardwareType:
			counts.ChangedTypes++
		}
		if !sameClassification(before.HardwareDetails, after.HardwareDetails) {
			out.Changes = append(out.Changes, replayChange{hex.EncodeToString(keyHash[:]), split, before.HardwareDetails, after.HardwareDetails})
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	if bounded.N <= 0 || len(seen) != metadata.Cohort {
		return out, fmt.Errorf("snapshot incomplete or over byte limit: %d/%d identities", len(seen), metadata.Cohort)
	}
	out.InputSHA256 = hex.EncodeToString(hash.Sum(nil))
	sort.Slice(out.Changes, func(i, j int) bool { return out.Changes[i].IdentityHash < out.Changes[j].IdentityHash })
	return out, nil
}

// Follow the projection's DNS-SD overflow compaction on the frozen records.
// Receiver compatibility needs exact event times and therefore prevents folding.
func compactReplayFacts(facts []discovery.HardwareFact) []discovery.HardwareFact {
	if len(facts) <= 512 {
		return facts
	}
	for _, fact := range facts {
		for _, signal := range fact.Signals {
			if !fact.Revoked && signal.Field == "dns_sd_receiver_implementation" {
				return facts
			}
		}
	}
	folded := make(map[string]discovery.HardwareFact)
	retained := make([]discovery.HardwareFact, 0, len(facts))
	for _, fact := range facts {
		if fact.Source != "dns_sd" || fact.Revoked || fact.AddressOnly {
			retained = append(retained, fact)
			continue
		}
		key, _ := json.Marshal(fact.Signals)
		previous, exists := folded[string(key)]
		if !exists {
			folded[string(key)] = fact
			continue
		}
		if previous.ObservedAt.After(fact.ObservedAt) || previous.ObservedAt.Equal(fact.ObservedAt) && previous.FactKey < fact.FactKey {
			fact, previous = previous, fact
		}
		if previous.FirstSeen.Before(fact.FirstSeen) {
			fact.FirstSeen = previous.FirstSeen
		}
		if previous.ActiveUntil.After(fact.ActiveUntil) {
			fact.ActiveUntil = previous.ActiveUntil
		}
		folded[string(key)] = fact
	}
	for _, fact := range folded {
		retained = append(retained, fact)
	}
	return retained
}

func sameClassification(a, b discovery.HardwareDetails) bool {
	return a.HardwareType == b.HardwareType && a.HardwareTypeStatus == b.HardwareTypeStatus &&
		a.HardwareModel == b.HardwareModel && a.HardwareModelStatus == b.HardwareModelStatus
}
