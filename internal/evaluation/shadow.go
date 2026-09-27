package evaluation

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/shadow"
	"proxy-sentinel/internal/store"
)

var evaluationLevels = []string{"confirmed", "high", "suspicious", "normal"}

type ShadowOptions struct {
	ShadowDir           string
	From                time.Time
	To                  time.Time
	RequiredDays        int
	SamplesPerDay       int
	ExportDir           string
	PostgresDSN         string
	Now                 time.Time
	MinCandidateReviews int
	MinNormalTruth      int
}

type ShadowEvaluationReport struct {
	GeneratedAt            string                 `json:"generated_at"`
	WindowFrom             string                 `json:"window_from,omitempty"`
	WindowTo               string                 `json:"window_to,omitempty"`
	RequiredDays           int                    `json:"required_days"`
	ObservedDays           int                    `json:"observed_days"`
	LongestContinuousDays  int                    `json:"longest_continuous_days"`
	DaysWithReviews        int                    `json:"days_with_reviews"`
	RunCount               int                    `json:"run_count"`
	TruncatedRunCount      int                    `json:"truncated_run_count"`
	MalformedEventCount    int                    `json:"malformed_event_count"`
	NormalizedEventCount   int                    `json:"normalized_event_count"`
	EvidenceCount          int                    `json:"evidence_count"`
	RiskSnapshotCount      int                    `json:"risk_snapshot_count"`
	EvaluatedSampleCount   int                    `json:"evaluated_sample_count"`
	ReviewedSnapshotCount  int                    `json:"reviewed_snapshot_count"`
	ReviewCoverage         float64                `json:"review_coverage"`
	CandidateReviewed      int                    `json:"candidate_reviewed"`
	NormalTruthCount       int                    `json:"normal_truth_count"`
	HighRiskPrecision      float64                `json:"high_risk_precision"`
	LevelStats             map[string]ReviewStats `json:"level_stats"`
	Daily                  []DailyReviewSummary   `json:"daily"`
	MissingReviewBuckets   []string               `json:"missing_review_buckets"`
	FalsePositiveReasons   []Count                `json:"false_positive_reasons"`
	FalsePositiveEvidence  []Count                `json:"false_positive_evidence"`
	RecommendedAdjustments []string               `json:"recommended_adjustments"`
	DailySampleExports     []string               `json:"daily_sample_exports,omitempty"`
	Ready                  bool                   `json:"ready"`
	Blockers               []string               `json:"blockers"`
}

type ReviewStats struct {
	Total         int     `json:"total"`
	Reviewed      int     `json:"reviewed"`
	Confirmed     int     `json:"confirmed"`
	FalsePositive int     `json:"false_positive"`
	Benign        int     `json:"benign"`
	NeedsMoreData int     `json:"needs_more_data"`
	Precision     float64 `json:"precision"`
}

type DailyReviewSummary struct {
	Date       string                 `json:"date"`
	RunCount   int                    `json:"run_count"`
	LevelStats map[string]ReviewStats `json:"level_stats"`
}

type Count struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type Sample struct {
	Date         string   `json:"date"`
	IP           string   `json:"ip"`
	SubjectType  string   `json:"subject_type,omitempty"`
	SubjectID    string   `json:"subject_id,omitempty"`
	AccountID    string   `json:"account_id,omitempty"`
	EndpointID   string   `json:"endpoint_id,omitempty"`
	Level        string   `json:"level"`
	Score        int      `json:"score"`
	Confidence   float64  `json:"confidence"`
	EvidenceIDs  []string `json:"evidence_ids"`
	ReviewStatus string   `json:"review_status"`
	ReviewReason string   `json:"review_reason,omitempty"`
	ReviewedBy   string   `json:"reviewed_by,omitempty"`
	ReviewedAt   string   `json:"reviewed_at,omitempty"`
	SourceRunID  string   `json:"source_run_id"`
	SnapshotTime string   `json:"snapshot_time"`
}

type runData struct {
	id       string
	date     string
	summary  shadow.RunSummary
	samples  []Sample
	evidence map[string]evidence.Evidence
}

func EvaluateShadow(opts ShadowOptions) (ShadowEvaluationReport, error) {
	if strings.TrimSpace(opts.ShadowDir) == "" {
		return ShadowEvaluationReport{}, fmt.Errorf("shadow directory is required")
	}
	if opts.RequiredDays <= 0 {
		opts.RequiredDays = 7
	}
	if opts.SamplesPerDay <= 0 {
		opts.SamplesPerDay = 30
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.MinCandidateReviews <= 0 {
		opts.MinCandidateReviews = 200
	}
	if opts.MinNormalTruth <= 0 {
		opts.MinNormalTruth = 200
	}
	if !opts.From.IsZero() && !opts.To.IsZero() && opts.From.After(opts.To) {
		return ShadowEvaluationReport{}, fmt.Errorf("from must not be after to")
	}

	labels, err := loadLabels(opts)
	if err != nil {
		return ShadowEvaluationReport{}, err
	}
	runs, err := readRuns(opts, labels)
	if err != nil {
		return ShadowEvaluationReport{}, err
	}
	report := buildReport(opts, runs)
	if opts.ExportDir != "" {
		exports, err := exportDailySamples(opts.ExportDir, runs, opts.SamplesPerDay)
		if err != nil {
			return ShadowEvaluationReport{}, err
		}
		report.DailySampleExports = exports
	}
	return report, nil
}

func loadLabels(opts ShadowOptions) ([]store.Label, error) {
	labels, err := readLabels(filepath.Join(opts.ShadowDir, "labels.jsonl"), opts.To)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.PostgresDSN) == "" {
		return labels, nil
	}
	postgres, err := store.NewPostgresStore(store.PostgresOptions{DSN: opts.PostgresDSN})
	if err != nil {
		return nil, fmt.Errorf("open postgres labels: %w", err)
	}
	defer postgres.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	databaseLabels, err := postgres.ListLabels(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("read postgres labels: %w", err)
	}
	seen := map[string]bool{}
	merged := make([]store.Label, 0, len(labels)+len(databaseLabels))
	for _, label := range append(databaseLabels, labels...) {
		if label.LabelID != "" && seen[label.LabelID] {
			continue
		}
		seen[label.LabelID] = true
		created, parseErr := time.Parse(time.RFC3339Nano, label.CreatedAt)
		if !opts.To.IsZero() && parseErr == nil && created.After(opts.To) {
			continue
		}
		merged = append(merged, label)
	}
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].CreatedAt > merged[j].CreatedAt })
	return merged, nil
}

func readRuns(opts ShadowOptions, labels []store.Label) ([]runData, error) {
	runsDir := filepath.Join(opts.ShadowDir, "runs")
	entries, err := os.ReadDir(runsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return []runData{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read shadow runs: %w", err)
	}
	result := []runData{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runDir := filepath.Join(runsDir, entry.Name())
		var summary shadow.RunSummary
		if err := readJSON(filepath.Join(runDir, "run-summary.json"), &summary); err != nil {
			continue
		}
		finished, err := time.Parse(time.RFC3339Nano, summary.FinishedAt)
		if err != nil || (!opts.From.IsZero() && finished.Before(opts.From)) || (!opts.To.IsZero() && finished.After(opts.To)) {
			continue
		}
		var batch risk.BatchResult
		if err := readJSON(filepath.Join(runDir, "risk-snapshots.json"), &batch); err != nil {
			return nil, fmt.Errorf("read run %s risk snapshots: %w", entry.Name(), err)
		}
		var evidenceResult evidence.Result
		if err := readJSON(filepath.Join(runDir, "evidence.json"), &evidenceResult); err != nil {
			return nil, fmt.Errorf("read run %s evidence: %w", entry.Name(), err)
		}
		evidenceByID := map[string]evidence.Evidence{}
		for _, item := range evidenceResult.Evidence {
			evidenceByID[item.EvidenceID] = item
		}
		run := runData{id: entry.Name(), date: finished.Format("2006-01-02"), summary: summary, evidence: evidenceByID}
		for _, snapshot := range batch.Snapshots {
			label, reviewed := latestMatchingLabel(snapshot, labels)
			sample := sampleFromSnapshot(run.id, run.date, snapshot)
			if reviewed {
				sample.ReviewStatus = label.Label
				sample.ReviewReason = label.Reason
				sample.ReviewedBy = label.CreatedBy
				sample.ReviewedAt = label.CreatedAt
			}
			run.samples = append(run.samples, sample)
		}
		result = append(result, run)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].date != result[j].date {
			return result[i].date < result[j].date
		}
		return result[i].id < result[j].id
	})
	return result, nil
}

func buildReport(opts ShadowOptions, runs []runData) ShadowEvaluationReport {
	report := ShadowEvaluationReport{
		GeneratedAt: opts.Now.Format(time.RFC3339Nano), RequiredDays: opts.RequiredDays,
		LevelStats: map[string]ReviewStats{}, Daily: []DailyReviewSummary{}, MissingReviewBuckets: []string{},
		FalsePositiveReasons: []Count{}, FalsePositiveEvidence: []Count{}, RecommendedAdjustments: []string{}, Blockers: []string{},
	}
	for _, level := range evaluationLevels {
		report.LevelStats[level] = ReviewStats{}
	}
	dailyRuns := map[string]int{}
	dailySamples := map[string][]Sample{}
	reasonCounts := map[string]int{}
	evidenceCounts := map[string]int{}
	evidenceByID := map[string]evidence.Evidence{}
	for _, run := range runs {
		report.RunCount++
		dailyRuns[run.date]++
		if run.summary.Truncated || run.summary.ZeekTruncated || run.summary.ZeekSoftwareTruncated {
			report.TruncatedRunCount++
		}
		report.MalformedEventCount += run.summary.Normalized.Malformed
		report.NormalizedEventCount += run.summary.Normalized.Emitted
		report.EvidenceCount += run.summary.EvidenceCount
		report.RiskSnapshotCount += len(run.samples)
		for id, item := range run.evidence {
			evidenceByID[id] = item
		}
		dailySamples[run.date] = append(dailySamples[run.date], run.samples...)
	}
	dates := sortedDates(dailyRuns)
	report.ObservedDays = len(dates)
	report.LongestContinuousDays = longestDateStreak(dates)
	if len(dates) > 0 {
		report.WindowFrom = dates[0] + "T00:00:00Z"
		report.WindowTo = dates[len(dates)-1] + "T23:59:59Z"
	}
	for _, date := range dates {
		dailySamples[date] = dedupeDailySamples(dailySamples[date])
		daily := DailyReviewSummary{Date: date, RunCount: dailyRuns[date], LevelStats: map[string]ReviewStats{}}
		dayReviewed := false
		for _, sample := range dailySamples[date] {
			report.EvaluatedSampleCount++
			level := normalizedLevel(sample.Level)
			stats := report.LevelStats[level]
			addReview(&stats, sample.ReviewStatus)
			report.LevelStats[level] = stats
			if isReviewed(sample.ReviewStatus) {
				report.ReviewedSnapshotCount++
			}
			if sample.ReviewStatus == "false_positive" || sample.ReviewStatus == "benign" {
				reason := strings.TrimSpace(sample.ReviewReason)
				if reason == "" {
					reason = "未填写原因"
				}
				reasonCounts[reason]++
				for _, evidenceID := range sample.EvidenceIDs {
					if item, ok := evidenceByID[evidenceID]; ok {
						evidenceCounts[item.Type]++
					}
				}
			}
		}
		for _, level := range evaluationLevels {
			stats := ReviewStats{}
			for _, sample := range dailySamples[date] {
				if normalizedLevel(sample.Level) == level {
					addReview(&stats, sample.ReviewStatus)
				}
			}
			stats.Precision = precision(stats)
			daily.LevelStats[level] = stats
			if stats.Reviewed > 0 {
				dayReviewed = true
			}
			if stats.Total > 0 && stats.Reviewed == 0 {
				report.MissingReviewBuckets = append(report.MissingReviewBuckets, date+":"+level)
			}
		}
		if dayReviewed {
			report.DaysWithReviews++
		}
		report.Daily = append(report.Daily, daily)
	}
	for level, stats := range report.LevelStats {
		stats.Precision = precision(stats)
		report.LevelStats[level] = stats
	}
	confirmed, high := report.LevelStats["confirmed"], report.LevelStats["high"]
	report.CandidateReviewed = confirmed.Confirmed + confirmed.FalsePositive + confirmed.Benign + high.Confirmed + high.FalsePositive + high.Benign
	report.NormalTruthCount = report.LevelStats["normal"].Benign
	report.HighRiskPrecision = precision(ReviewStats{Confirmed: confirmed.Confirmed + high.Confirmed, FalsePositive: confirmed.FalsePositive + high.FalsePositive, Benign: confirmed.Benign + high.Benign})
	if report.EvaluatedSampleCount > 0 {
		report.ReviewCoverage = float64(report.ReviewedSnapshotCount) / float64(report.EvaluatedSampleCount)
	}
	report.FalsePositiveReasons = sortedCounts(reasonCounts, 10)
	report.FalsePositiveEvidence = sortedCounts(evidenceCounts, 10)
	report.RecommendedAdjustments = recommendations(report)
	if report.LongestContinuousDays < opts.RequiredDays {
		report.Blockers = append(report.Blockers, fmt.Sprintf("连续影子运行仅 %d 天，要求至少 %d 天", report.LongestContinuousDays, opts.RequiredDays))
	}
	if report.RiskSnapshotCount == 0 {
		report.Blockers = append(report.Blockers, "评估窗口内没有风险快照")
	}
	if report.DaysWithReviews < opts.RequiredDays {
		report.Blockers = append(report.Blockers, fmt.Sprintf("仅 %d 天包含人工复核，要求至少 %d 天", report.DaysWithReviews, opts.RequiredDays))
	}
	if len(report.MissingReviewBuckets) > 0 {
		report.Blockers = append(report.Blockers, fmt.Sprintf("存在 %d 个有样本但未复核的日期/等级分桶", len(report.MissingReviewBuckets)))
	}
	if report.CandidateReviewed < opts.MinCandidateReviews {
		report.Blockers = append(report.Blockers, fmt.Sprintf("高风险候选有效复核仅 %d 条，要求至少 %d 条", report.CandidateReviewed, opts.MinCandidateReviews))
	}
	if report.NormalTruthCount < opts.MinNormalTruth {
		report.Blockers = append(report.Blockers, fmt.Sprintf("正常主体人工真值仅 %d 条，要求至少 %d 条", report.NormalTruthCount, opts.MinNormalTruth))
	}
	if report.HighRiskPrecision < 0.95 {
		report.Blockers = append(report.Blockers, fmt.Sprintf("高风险人工确认率 %.1f%%，要求至少 95%%", report.HighRiskPrecision*100))
	}
	if report.TruncatedRunCount > 0 || report.MalformedEventCount > 0 {
		report.Blockers = append(report.Blockers, fmt.Sprintf("采集质量未通过：截断运行=%d，畸形事件=%d", report.TruncatedRunCount, report.MalformedEventCount))
	}
	report.Ready = len(report.Blockers) == 0
	return report
}

func exportDailySamples(exportDir string, runs []runData, perLevel int) ([]string, error) {
	if err := os.MkdirAll(exportDir, 0o755); err != nil {
		return nil, fmt.Errorf("create daily export directory: %w", err)
	}
	byDate := map[string][]Sample{}
	for _, run := range runs {
		byDate[run.date] = append(byDate[run.date], run.samples...)
	}
	exports := []string{}
	for _, date := range sortedDatesFromSamples(byDate) {
		byDate[date] = dedupeDailySamples(byDate[date])
		selected := []Sample{}
		for _, level := range evaluationLevels {
			candidates := []Sample{}
			for _, sample := range byDate[date] {
				if normalizedLevel(sample.Level) == level {
					candidates = append(candidates, sample)
				}
			}
			sort.SliceStable(candidates, func(i, j int) bool {
				if candidates[i].Score != candidates[j].Score {
					return candidates[i].Score > candidates[j].Score
				}
				return candidates[i].IP < candidates[j].IP
			})
			if len(candidates) > perLevel {
				candidates = candidates[:perLevel]
			}
			selected = append(selected, candidates...)
		}
		path := filepath.Join(exportDir, date+"-review-samples.json")
		if err := writeJSON(path, map[string]any{"date": date, "samples_per_level": perLevel, "samples": selected}); err != nil {
			return nil, err
		}
		exports = append(exports, path)
	}
	return exports, nil
}

func dedupeDailySamples(samples []Sample) []Sample {
	latest := map[string]Sample{}
	for _, sample := range samples {
		key := sampleKey(sample)
		current, ok := latest[key]
		if !ok || sample.SnapshotTime > current.SnapshotTime || (sample.SnapshotTime == current.SnapshotTime && sample.SourceRunID > current.SourceRunID) {
			latest[key] = sample
		}
	}
	result := make([]Sample, 0, len(latest))
	for _, sample := range latest {
		result = append(result, sample)
	}
	sort.Slice(result, func(i, j int) bool {
		if normalizedLevel(result[i].Level) != normalizedLevel(result[j].Level) {
			return normalizedLevel(result[i].Level) < normalizedLevel(result[j].Level)
		}
		return sampleKey(result[i]) < sampleKey(result[j])
	})
	return result
}

func sampleKey(sample Sample) string {
	if sample.SubjectType != "" && sample.SubjectID != "" {
		return strings.ToLower(sample.SubjectType) + ":" + sample.SubjectID
	}
	if sample.AccountID != "" {
		return "account:" + sample.AccountID
	}
	if sample.EndpointID != "" {
		return "endpoint:" + sample.EndpointID
	}
	return "ip:" + sample.IP
}

func readLabels(path string, to time.Time) ([]store.Label, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []store.Label{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open labels: %w", err)
	}
	defer file.Close()
	labels := []store.Label{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var label store.Label
		if err := json.Unmarshal(scanner.Bytes(), &label); err != nil {
			return nil, fmt.Errorf("decode labels: %w", err)
		}
		created, err := time.Parse(time.RFC3339Nano, label.CreatedAt)
		if !to.IsZero() && err == nil && created.After(to) {
			continue
		}
		labels = append(labels, label)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read labels: %w", err)
	}
	sort.SliceStable(labels, func(i, j int) bool { return labels[i].CreatedAt > labels[j].CreatedAt })
	return labels, nil
}

func latestMatchingLabel(snapshot risk.Snapshot, labels []store.Label) (store.Label, bool) {
	keys := map[string]bool{}
	add := func(kind, id string) {
		kind, id = strings.ToLower(strings.TrimSpace(kind)), strings.TrimSpace(id)
		if kind != "" && id != "" {
			keys[kind+":"+id] = true
		}
	}
	if snapshot.SubjectType != "" && snapshot.SubjectID != "" {
		add(snapshot.SubjectType, snapshot.SubjectID)
	} else if snapshot.AccountID != "" {
		add("account", snapshot.AccountID)
	} else if snapshot.EndpointID != "" {
		add("endpoint", snapshot.EndpointID)
	} else {
		add("ip", snapshot.IP)
	}
	evidenceIDs := map[string]bool{}
	for _, id := range snapshot.EvidenceIDs {
		evidenceIDs[id] = true
	}
	for _, label := range labels {
		if !keys[strings.ToLower(strings.TrimSpace(label.TargetType))+":"+strings.TrimSpace(label.TargetID)] {
			continue
		}
		for _, id := range label.EvidenceIDs {
			if evidenceIDs[id] {
				return label, true
			}
		}
	}
	return store.Label{}, false
}

func sampleFromSnapshot(runID, date string, snapshot risk.Snapshot) Sample {
	return Sample{Date: date, IP: snapshot.IP, SubjectType: snapshot.SubjectType, SubjectID: snapshot.SubjectID,
		AccountID: snapshot.AccountID, EndpointID: snapshot.EndpointID, Level: normalizedLevel(snapshot.Level), Score: snapshot.Score,
		Confidence: snapshot.Confidence, EvidenceIDs: append([]string{}, snapshot.EvidenceIDs...), ReviewStatus: "unreviewed",
		SourceRunID: runID, SnapshotTime: snapshot.UpdatedAt}
}

// ReviewSamplesWithLabels refreshes only the sample status. Aggregate coverage
// remains tied to the generated report until the next scheduled evaluation.
func ReviewSamplesWithLabels(samples []Sample, labels []store.Label) []Sample {
	ordered := append([]store.Label(nil), labels...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].CreatedAt > ordered[j].CreatedAt })
	result := append([]Sample(nil), samples...)
	for i := range result {
		item := &result[i]
		snapshot := risk.Snapshot{IP: item.IP, SubjectType: item.SubjectType, SubjectID: item.SubjectID, AccountID: item.AccountID, EndpointID: item.EndpointID, EvidenceIDs: item.EvidenceIDs}
		if label, found := latestMatchingLabel(snapshot, ordered); found {
			item.ReviewStatus, item.ReviewReason, item.ReviewedBy, item.ReviewedAt = label.Label, label.Reason, label.CreatedBy, label.CreatedAt
		}
	}
	return result
}

func addReview(stats *ReviewStats, status string) {
	stats.Total++
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "confirmed", "confirmed_proxy":
		stats.Reviewed++
		stats.Confirmed++
	case "false_positive":
		stats.Reviewed++
		stats.FalsePositive++
	case "benign":
		stats.Reviewed++
		stats.Benign++
	case "needs_more_data":
		stats.Reviewed++
		stats.NeedsMoreData++
	}
}

func isReviewed(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "confirmed", "confirmed_proxy", "false_positive", "benign", "needs_more_data":
		return true
	default:
		return false
	}
}

func precision(stats ReviewStats) float64 {
	decided := stats.Confirmed + stats.FalsePositive + stats.Benign
	if decided == 0 {
		return 0
	}
	return float64(stats.Confirmed) / float64(decided)
}

func normalizedLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "confirmed", "high", "suspicious":
		return strings.ToLower(strings.TrimSpace(level))
	default:
		return "normal"
	}
}

func longestDateStreak(dates []string) int {
	longest, current := 0, 0
	var previous time.Time
	for _, raw := range dates {
		date, err := time.Parse("2006-01-02", raw)
		if err != nil {
			continue
		}
		if previous.IsZero() || date.Sub(previous) == 24*time.Hour {
			current++
		} else {
			current = 1
		}
		if current > longest {
			longest = current
		}
		previous = date
	}
	return longest
}

func sortedDates(values map[string]int) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedDatesFromSamples(values map[string][]Sample) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedCounts(values map[string]int, limit int) []Count {
	result := make([]Count, 0, len(values))
	for value, count := range values {
		result = append(result, Count{Value: value, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Value < result[j].Value
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result
}

func recommendations(report ShadowEvaluationReport) []string {
	result := []string{}
	for _, item := range report.FalsePositiveEvidence {
		result = append(result, fmt.Sprintf("复查证据类型 %s：在误报/良性样本中出现 %d 次，优先补充规则约束或负证据", item.Value, item.Count))
		if len(result) == 3 {
			break
		}
	}
	for _, item := range report.FalsePositiveReasons {
		result = append(result, fmt.Sprintf("维护误报来源“%s”的白名单或已知应用分类（%d 次）", item.Value, item.Count))
		if len(result) == 6 {
			break
		}
	}
	if len(result) == 0 {
		result = append(result, "完成各风险等级人工复核后，再根据误报证据与原因生成规则调整建议")
	}
	return result
}

func readJSON(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(target)
}

func writeJSON(path string, value any) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
