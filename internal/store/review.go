package store

import (
	"sort"
	"strings"

	"proxy-sentinel/internal/risk"
)

const ReviewStatusUnreviewed = "unreviewed"

func applyLatestReviewLabels(items []risk.Snapshot, labels map[string]Label) []risk.Snapshot {
	result := make([]risk.Snapshot, 0, len(items))
	for _, item := range items {
		result = append(result, applyLatestReviewLabel(item, labels))
	}
	return result
}

func applyLatestReviewLabel(item risk.Snapshot, labels map[string]Label) risk.Snapshot {
	item.ReviewStatus = ReviewStatusUnreviewed
	item.ReviewLabelID = ""
	item.ReviewReason = ""
	item.ReviewedBy = ""
	item.ReviewedAt = ""
	for _, key := range riskReviewKeys(item) {
		label, ok := labels[key]
		if !ok {
			continue
		}
		item.ReviewStatus = label.Label
		item.ReviewLabelID = label.LabelID
		item.ReviewReason = label.Reason
		item.ReviewedBy = label.CreatedBy
		item.ReviewedAt = label.CreatedAt
		item = risk.ApplyNegativeEvidence(item, negativeEvidenceFromLabel(label))
		return item
	}
	return item
}

func latestLabelMap(labels []Label) map[string]Label {
	sort.SliceStable(labels, func(i, j int) bool {
		if labels[i].CreatedAt == labels[j].CreatedAt {
			return labels[i].LabelID > labels[j].LabelID
		}
		return labels[i].CreatedAt > labels[j].CreatedAt
	})
	result := map[string]Label{}
	for _, label := range labels {
		key := reviewLabelKey(label.TargetType, label.TargetID)
		if key == "" {
			continue
		}
		if _, ok := result[key]; ok {
			continue
		}
		result[key] = label
	}
	return result
}

func riskReviewKeys(item risk.Snapshot) []string {
	keys := []string{}
	add := func(targetType, targetID string) {
		key := reviewLabelKey(targetType, targetID)
		if key == "" || stringSliceContains(keys, key) {
			return
		}
		keys = append(keys, key)
	}
	add(item.SubjectType, item.SubjectID)
	add("account", item.AccountID)
	add("endpoint", item.EndpointID)
	add("ip", item.IP)
	return keys
}

func reviewLabelKey(targetType, targetID string) string {
	targetType = strings.TrimSpace(strings.ToLower(targetType))
	targetID = strings.TrimSpace(targetID)
	if targetType == "" || targetID == "" {
		return ""
	}
	return targetType + ":" + targetID
}

func pendingReviewCount(items []risk.Snapshot) int {
	count := 0
	for _, item := range items {
		if item.ReviewStatus != "" && item.ReviewStatus != ReviewStatusUnreviewed {
			continue
		}
		if item.Level == "high" || item.Level == "confirmed" {
			count++
		}
	}
	return count
}

func negativeEvidenceFromLabel(label Label) []risk.NegativeEvidence {
	labelKind := strings.TrimSpace(strings.ToLower(label.Label))
	reason := strings.TrimSpace(label.Reason)
	switch labelKind {
	case "false_positive":
		return []risk.NegativeEvidence{{
			Type:       negativeEvidenceTypeFromReason(reason, "manual_false_positive"),
			Source:     "label:" + label.LabelID,
			Reason:     firstNonEmpty(reason, "人工复核误报"),
			ScoreDelta: -80,
			MaxScore:   20,
			LevelCap:   "normal",
		}}
	case "benign":
		return []risk.NegativeEvidence{{
			Type:       negativeEvidenceTypeFromReason(reason, "manual_benign"),
			Source:     "label:" + label.LabelID,
			Reason:     firstNonEmpty(reason, "人工复核良性"),
			ScoreDelta: -60,
			MaxScore:   29,
			LevelCap:   "normal",
		}}
	case "needs_more_data":
		return []risk.NegativeEvidence{{
			Type:       "needs_more_data",
			Source:     "label:" + label.LabelID,
			Reason:     firstNonEmpty(reason, "人工复核需要更多数据"),
			ScoreDelta: -5,
			LevelCap:   "high",
		}}
	default:
		return nil
	}
}

func negativeEvidenceTypeFromReason(reason string, fallback string) string {
	lower := strings.ToLower(reason)
	switch {
	case strings.Contains(reason, "白名单") || strings.Contains(lower, "whitelist"):
		return "whitelist"
	case strings.Contains(reason, "测试") || strings.Contains(lower, "test"):
		return "test_device"
	case strings.Contains(reason, "基础设施") || strings.Contains(reason, "网关") || strings.Contains(lower, "dns") || strings.Contains(lower, "dhcp") || strings.Contains(reason, "服务器"):
		return "infrastructure"
	case strings.Contains(reason, "下载器") || strings.Contains(reason, "系统服务") || strings.Contains(reason, "系统更新") || strings.Contains(reason, "办公软件") || strings.Contains(reason, "网盘") || strings.Contains(reason, "游戏") || strings.Contains(reason, "加速器"):
		return "known_application"
	default:
		return fallback
	}
}
