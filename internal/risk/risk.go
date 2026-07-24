package risk

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
)

type Snapshot struct {
	IP                string   `json:"ip"`
	Score             int      `json:"score"`
	Level             string   `json:"level"`
	Confidence        float64  `json:"confidence"`
	Window            string   `json:"window"`
	EvidenceIDs       []string `json:"evidence_ids"`
	Summary           string   `json:"summary"`
	RecommendedAction string   `json:"recommended_action"`
	UpdatedAt         string   `json:"updated_at"`
}

type InspectOptions struct {
	IP string
}

func InspectFile(inputPath string, opts InspectOptions) (Snapshot, error) {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return Snapshot{}, err
	}
	defer closeInput()

	return Inspect(input, opts)
}

func Inspect(r io.Reader, opts InspectOptions) (Snapshot, error) {
	if opts.IP == "" {
		return Snapshot{}, fmt.Errorf("ip is required")
	}
	allEvidence, err := readEvidence(r)
	if err != nil {
		return Snapshot{}, err
	}

	selected := make([]evidence.Evidence, 0)
	for _, item := range allEvidence {
		if item.IP == opts.IP {
			selected = append(selected, item)
		}
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Score == selected[j].Score {
			return selected[i].EvidenceID < selected[j].EvidenceID
		}
		return selected[i].Score > selected[j].Score
	})

	if len(selected) == 0 {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		return Snapshot{
			IP:                opts.IP,
			Score:             0,
			Level:             "normal",
			Confidence:        0,
			Window:            "none",
			EvidenceIDs:       []string{},
			Summary:           "未发现该 IP 的有效风险证据",
			RecommendedAction: "record",
			UpdatedAt:         now,
		}, nil
	}

	score := combinedScore(selected)
	level := levelFor(score, selected)
	updatedAt := latestCreatedAt(selected)
	window := selected[0].Window
	if window == "" {
		window = "unknown"
	}

	return Snapshot{
		IP:                opts.IP,
		Score:             score,
		Level:             level,
		Confidence:        combinedConfidence(selected),
		Window:            window,
		EvidenceIDs:       evidenceIDs(selected),
		Summary:           summaryFor(selected, level),
		RecommendedAction: actionFor(level),
		UpdatedAt:         updatedAt,
	}, nil
}

func readEvidence(r io.Reader) ([]evidence.Evidence, error) {
	var result evidence.Result
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("read evidence input: %w", err)
	}
	if result.Evidence != nil {
		return result.Evidence, nil
	}
	return nil, fmt.Errorf("evidence input does not contain evidence array")
}

func combinedScore(items []evidence.Evidence) int {
	total := 0
	types := map[string]struct{}{}
	weakOnly := true
	for _, item := range items {
		total += item.Score
		types[item.Type] = struct{}{}
		if !isWeakEvidence(item.Type) {
			weakOnly = false
		}
	}
	if total > 100 {
		total = 100
	}
	if weakOnly {
		if len(types) <= 1 && total > 29 {
			return 29
		}
		if total > 45 {
			return 45
		}
	}
	return total
}

func levelFor(score int, items []evidence.Evidence) string {
	if score < 30 {
		return "normal"
	}
	if score < 60 {
		return "suspicious"
	}
	if score < 80 {
		return "high"
	}
	if strongEvidenceTypeCount(items) >= 2 {
		return "confirmed"
	}
	return "high"
}

func actionFor(level string) string {
	switch level {
	case "confirmed":
		return "shadow_confirm_review"
	case "high":
		return "shadow_manual_review"
	case "suspicious":
		return "shadow_watch"
	default:
		return "record"
	}
}

func combinedConfidence(items []evidence.Evidence) float64 {
	if len(items) == 0 {
		return 0
	}
	weighted := 0.0
	totalScore := 0
	for _, item := range items {
		weighted += item.Confidence * float64(item.Score)
		totalScore += item.Score
	}
	if totalScore == 0 {
		return 0
	}
	return round2(weighted / float64(totalScore))
}

func round2(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}

func evidenceIDs(items []evidence.Evidence) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.EvidenceID)
	}
	sort.Strings(ids)
	return ids
}

func latestCreatedAt(items []evidence.Evidence) string {
	latest := ""
	for _, item := range items {
		if item.CreatedAt > latest {
			latest = item.CreatedAt
		}
	}
	if latest == "" {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	return latest
}

func summaryFor(items []evidence.Evidence, level string) string {
	typeNames := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		if _, ok := seen[item.Type]; ok {
			continue
		}
		seen[item.Type] = struct{}{}
		typeNames = append(typeNames, item.Type)
	}
	sort.Strings(typeNames)
	if len(typeNames) == 0 {
		return "未发现有效风险证据"
	}
	return fmt.Sprintf("%s 级别风险由 %s 证据共同贡献；当前仍为影子判断，需要结合负证据和人工复核", level, strings.Join(typeNames, "、"))
}

func isWeakEvidence(evidenceType string) bool {
	return evidenceType == "domain_diversity" || evidenceType == "port_distribution"
}

func strongEvidenceTypeCount(items []evidence.Evidence) int {
	types := map[string]struct{}{}
	for _, item := range items {
		if isWeakEvidence(item.Type) {
			continue
		}
		types[item.Type] = struct{}{}
	}
	return len(types)
}

func openInput(path string) (io.Reader, func() error, error) {
	if path == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open input: %w", err)
	}
	return file, file.Close, nil
}
