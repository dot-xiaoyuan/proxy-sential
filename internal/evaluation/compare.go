package evaluation

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"proxy-sentinel/internal/risk"
)

type LegacyAssessment struct {
	IP       string `json:"ip"`
	Level    string `json:"level"`
	Score    int    `json:"score"`
	Detected bool   `json:"detected"`
}
type ComparisonItem struct {
	IP             string `json:"ip"`
	CurrentLevel   string `json:"current_level"`
	CurrentScore   int    `json:"current_score"`
	LegacyLevel    string `json:"legacy_level"`
	LegacyScore    int    `json:"legacy_score"`
	Classification string `json:"classification"`
	Reason         string `json:"reason,omitempty"`
}
type ComparisonReport struct {
	CurrentCount int              `json:"current_count"`
	LegacyCount  int              `json:"legacy_count"`
	Agreement    int              `json:"agreement"`
	CurrentOnly  int              `json:"current_only"`
	LegacyOnly   int              `json:"legacy_only"`
	LevelChanged int              `json:"level_changed"`
	Items        []ComparisonItem `json:"items"`
}

func Compare(current risk.BatchResult, legacy []LegacyAssessment) ComparisonReport {
	currentByIP := map[string]risk.Snapshot{}
	legacyByIP := map[string]LegacyAssessment{}
	keys := map[string]struct{}{}
	for _, item := range current.Snapshots {
		if item.IP != "" {
			currentByIP[item.IP] = item
			keys[item.IP] = struct{}{}
		}
	}
	for _, item := range legacy {
		if item.IP != "" {
			if item.Level == "" {
				if item.Detected {
					item.Level = "confirmed"
				} else {
					item.Level = "normal"
				}
			}
			legacyByIP[item.IP] = item
			keys[item.IP] = struct{}{}
		}
	}
	ips := make([]string, 0, len(keys))
	for ip := range keys {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	report := ComparisonReport{CurrentCount: len(currentByIP), LegacyCount: len(legacyByIP), Items: []ComparisonItem{}}
	for _, ip := range ips {
		c, cok := currentByIP[ip]
		l, lok := legacyByIP[ip]
		item := ComparisonItem{IP: ip, CurrentLevel: c.Level, CurrentScore: c.Score, LegacyLevel: l.Level, LegacyScore: l.Score}
		switch {
		case !lok:
			item.Classification = "current_only"
			item.Reason = "仅新系统产生风险对象"
			report.CurrentOnly++
		case !cok:
			item.Classification = "legacy_only"
			item.Reason = "仅旧系统产生风险对象"
			report.LegacyOnly++
		case c.Level == l.Level:
			item.Classification = "agreement"
			report.Agreement++
		default:
			item.Classification = "level_changed"
			item.Reason = "新旧系统风险等级不同，需人工复核证据"
			report.LevelChanged++
		}
		report.Items = append(report.Items, item)
	}
	return report
}

func ReadLegacy(r io.Reader) ([]LegacyAssessment, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	trim := strings.TrimSpace(string(data))
	if trim == "" {
		return []LegacyAssessment{}, nil
	}
	if trim[0] == '[' {
		var items []LegacyAssessment
		return items, json.Unmarshal(data, &items)
	}
	if trim[0] == '{' {
		var wrapper struct {
			Items     []LegacyAssessment `json:"items"`
			Snapshots []LegacyAssessment `json:"snapshots"`
		}
		if err := json.Unmarshal(data, &wrapper); err != nil {
			return nil, err
		}
		if len(wrapper.Items) > 0 {
			return wrapper.Items, nil
		}
		return wrapper.Snapshots, nil
	}
	reader := csv.NewReader(strings.NewReader(trim))
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return []LegacyAssessment{}, nil
	}
	header := map[string]int{}
	for i, name := range rows[0] {
		header[strings.TrimSpace(name)] = i
	}
	if _, ok := header["ip"]; !ok {
		return nil, fmt.Errorf("legacy CSV requires ip column")
	}
	items := []LegacyAssessment{}
	for _, row := range rows[1:] {
		get := func(key string) string {
			index, ok := header[key]
			if !ok || index >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[index])
		}
		score, _ := strconv.Atoi(get("score"))
		detected, _ := strconv.ParseBool(get("detected"))
		items = append(items, LegacyAssessment{IP: get("ip"), Level: get("level"), Score: score, Detected: detected})
	}
	return items, nil
}
