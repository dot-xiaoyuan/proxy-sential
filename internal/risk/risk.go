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
	IP                   string   `json:"ip"`
	Score                int      `json:"score"`
	Level                string   `json:"level"`
	Confidence           float64  `json:"confidence"`
	Window               string   `json:"window"`
	EvidenceIDs          []string `json:"evidence_ids"`
	Summary              string   `json:"summary"`
	RecommendedAction    string   `json:"recommended_action"`
	UpdatedAt            string   `json:"updated_at"`
	SuspectedDeviceCount int      `json:"suspected_device_count"`
	DeviceSummary        string   `json:"device_summary,omitempty"`
	DeviceConfidence     float64  `json:"device_confidence"`
}

type InspectOptions struct {
	IP string
}

type BatchResult struct {
	Snapshots []Snapshot `json:"snapshots"`
}

type ListOptions struct {
	MinLevel string
	Limit    int
}

type ListResult struct {
	MinLevel  string     `json:"min_level"`
	Limit     int        `json:"limit"`
	Snapshots []Snapshot `json:"snapshots"`
}

func InspectFile(inputPath string, opts InspectOptions) (Snapshot, error) {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return Snapshot{}, err
	}
	defer closeInput()

	return Inspect(input, opts)
}

func BatchFile(inputPath, outputPath string) (BatchResult, error) {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return BatchResult{}, err
	}
	defer closeInput()

	output, closeOutput, err := openOutput(outputPath)
	if err != nil {
		return BatchResult{}, err
	}
	defer closeOutput()

	result, err := Batch(input)
	if err != nil {
		return BatchResult{}, err
	}
	if err := writeJSON(output, result); err != nil {
		return BatchResult{}, fmt.Errorf("write risk batch: %w", err)
	}
	return result, nil
}

func Batch(r io.Reader) (BatchResult, error) {
	allEvidence, err := readEvidence(r)
	if err != nil {
		return BatchResult{}, err
	}

	evidenceByIP := map[string][]evidence.Evidence{}
	for _, item := range allEvidence {
		if item.IP == "" {
			continue
		}
		evidenceByIP[item.IP] = append(evidenceByIP[item.IP], item)
	}

	ips := make([]string, 0, len(evidenceByIP))
	for ip := range evidenceByIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	result := BatchResult{Snapshots: []Snapshot{}}
	for _, ip := range ips {
		result.Snapshots = append(result.Snapshots, snapshotFor(ip, evidenceByIP[ip]))
	}
	return result, nil
}

func ListFile(inputPath, outputPath string, opts ListOptions) (ListResult, error) {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return ListResult{}, err
	}
	defer closeInput()

	output, closeOutput, err := openOutput(outputPath)
	if err != nil {
		return ListResult{}, err
	}
	defer closeOutput()

	result, err := List(input, opts)
	if err != nil {
		return ListResult{}, err
	}
	if err := writeJSON(output, result); err != nil {
		return ListResult{}, fmt.Errorf("write risk list: %w", err)
	}
	return result, nil
}

func List(r io.Reader, opts ListOptions) (ListResult, error) {
	minLevel := opts.MinLevel
	if minLevel == "" {
		minLevel = "suspicious"
	}
	minRank, ok := levelRank(minLevel)
	if !ok {
		return ListResult{}, fmt.Errorf("unknown min level: %s", minLevel)
	}

	batch, err := readBatch(r)
	if err != nil {
		return ListResult{}, err
	}
	snapshots := make([]Snapshot, 0, len(batch.Snapshots))
	for _, snapshot := range batch.Snapshots {
		rank, ok := levelRank(snapshot.Level)
		if !ok || rank < minRank {
			continue
		}
		snapshots = append(snapshots, snapshot)
	}
	sort.Slice(snapshots, func(i, j int) bool {
		leftRank, _ := levelRank(snapshots[i].Level)
		rightRank, _ := levelRank(snapshots[j].Level)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if snapshots[i].Score != snapshots[j].Score {
			return snapshots[i].Score > snapshots[j].Score
		}
		return snapshots[i].IP < snapshots[j].IP
	})
	if opts.Limit > 0 && len(snapshots) > opts.Limit {
		snapshots = snapshots[:opts.Limit]
	}

	return ListResult{MinLevel: minLevel, Limit: opts.Limit, Snapshots: snapshots}, nil
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

	return snapshotFor(opts.IP, selected), nil
}

func snapshotFor(ip string, selected []evidence.Evidence) Snapshot {
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Score == selected[j].Score {
			return selected[i].EvidenceID < selected[j].EvidenceID
		}
		return selected[i].Score > selected[j].Score
	})

	score := combinedScore(selected)
	level := levelFor(score, selected)
	updatedAt := latestCreatedAt(selected)
	window := selected[0].Window
	if window == "" {
		window = "unknown"
	}

	return Snapshot{
		IP:                ip,
		Score:             score,
		Level:             level,
		Confidence:        combinedConfidence(selected),
		Window:            window,
		EvidenceIDs:       evidenceIDs(selected),
		Summary:           summaryFor(selected, level),
		RecommendedAction: actionFor(level),
		UpdatedAt:         updatedAt,
	}
}

func readEvidence(r io.Reader) ([]evidence.Evidence, error) {
	var result evidence.Result
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("read evidence input: %w", err)
	}
	if result.Evidence == nil {
		return []evidence.Evidence{}, nil
	}
	return result.Evidence, nil
}

func readBatch(r io.Reader) (BatchResult, error) {
	var result BatchResult
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&result); err != nil {
		return BatchResult{}, fmt.Errorf("read risk batch input: %w", err)
	}
	if result.Snapshots == nil {
		return BatchResult{Snapshots: []Snapshot{}}, nil
	}
	return result, nil
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
	return evidenceType == "multi_user_agent" || evidenceType == "domain_diversity" || evidenceType == "port_distribution"
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

func levelRank(level string) (int, bool) {
	switch level {
	case "normal":
		return 0, true
	case "suspicious":
		return 1, true
	case "high":
		return 2, true
	case "confirmed":
		return 3, true
	default:
		return 0, false
	}
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

func openOutput(path string) (io.Writer, func() error, error) {
	if path == "-" || path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output: %w", err)
	}
	return file, file.Close, nil
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
