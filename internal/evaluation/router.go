package evaluation

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/adapter/suricata"
	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
)

type RouterGoldenManifest struct {
	AsOf  string             `json:"as_of,omitempty"`
	Cases []RouterGoldenCase `json:"cases"`
}

type RouterGoldenCase struct {
	ID             string `json:"id"`
	Input          string `json:"input"`
	InputKind      string `json:"input_kind"`
	ExpectedBrand  string `json:"expected_brand,omitempty"`
	ExpectedRole   string `json:"expected_role,omitempty"`
	ExpectedStatus string `json:"expected_status,omitempty"`
	ExpectedRouter bool   `json:"expected_router"`
	OUIOnly        bool   `json:"oui_only,omitempty"`
	AsOf           string `json:"as_of,omitempty"`
}

type RouterEvaluationCase struct {
	ID             string `json:"id"`
	Passed         bool   `json:"passed"`
	ExpectedBrand  string `json:"expected_brand,omitempty"`
	ExpectedRole   string `json:"expected_role,omitempty"`
	ExpectedStatus string `json:"expected_status,omitempty"`
	ActualBrand    string `json:"actual_brand,omitempty"`
	ActualRole     string `json:"actual_role,omitempty"`
	ActualStatus   string `json:"actual_status,omitempty"`
	Confidence     int    `json:"confidence,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type RouterEvaluationReport struct {
	TotalSamples          int                    `json:"total_samples"`
	CandidateCount        int                    `json:"candidate_count"`
	LikelyCount           int                    `json:"likely_count"`
	ConfirmedCount        int                    `json:"confirmed_count"`
	RouterPrecision       float64                `json:"huawei_h3c_router_precision"`
	RouterRecall          float64                `json:"huawei_h3c_router_recall"`
	RoleFalsePositiveRate map[string]float64     `json:"role_false_positive_rate"`
	OUIOnlyMisconfirmed   int                    `json:"oui_only_misconfirmed"`
	SourceDistribution    map[string]int         `json:"source_distribution"`
	UnableToAssociate     int                    `json:"unable_to_associate"`
	ExpiredEvidence       int                    `json:"expired_evidence"`
	Passed                int                    `json:"passed"`
	Failed                int                    `json:"failed"`
	Cases                 []RouterEvaluationCase `json:"cases"`
}

func EvaluateRouters(manifestPath string) (RouterEvaluationReport, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return RouterEvaluationReport{}, err
	}
	var manifest RouterGoldenManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return RouterEvaluationReport{}, fmt.Errorf("decode router golden manifest: %w", err)
	}
	if len(manifest.Cases) == 0 {
		return RouterEvaluationReport{}, fmt.Errorf("router golden manifest has no cases")
	}
	base := filepath.Dir(manifestPath)
	report := RouterEvaluationReport{TotalSamples: len(manifest.Cases), RoleFalsePositiveRate: map[string]float64{}, SourceDistribution: map[string]int{}, Cases: []RouterEvaluationCase{}}
	roleTotals, roleFalse := map[string]int{}, map[string]int{}
	truePositive, falsePositive, falseNegative := 0, 0, 0
	for _, item := range manifest.Cases {
		if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.Input) == "" {
			return report, fmt.Errorf("router golden case requires id and input")
		}
		inputPath := item.Input
		if !filepath.IsAbs(inputPath) {
			inputPath = filepath.Join(base, inputPath)
		}
		events, loadErr := loadRouterGoldenEvents(inputPath, item.InputKind)
		if loadErr != nil {
			return report, fmt.Errorf("case %s: %w", item.ID, loadErr)
		}
		asOf, parseErr := routerEvaluationTime(firstNonEmptyEvaluation(item.AsOf, manifest.AsOf))
		if parseErr != nil {
			return report, fmt.Errorf("case %s: %w", item.ID, parseErr)
		}
		result, analyzeErr := evidence.AnalyzeRouters(events, evidence.RouterOptions{AsOf: asOf, ShadowMode: true})
		if analyzeErr != nil {
			return report, fmt.Errorf("case %s: %w", item.ID, analyzeErr)
		}
		for _, assessment := range result.Assessments {
			switch assessment.Status {
			case "candidate":
				report.CandidateCount++
			case "likely":
				report.LikelyCount++
			case "confirmed":
				report.ConfirmedCount++
			}
			if assessment.Ambiguous {
				report.UnableToAssociate++
			}
		}
		for _, routerEvidence := range result.Evidence {
			if routerEvidence.Expired {
				report.ExpiredEvidence++
			}
			if routerEvidence.SourceFamily != "derived" {
				report.SourceDistribution[routerEvidence.SourceFamily]++
			}
		}
		var actual evidence.RouterAssessment
		if len(result.Assessments) > 0 {
			actual = result.Assessments[0]
		}
		caseReport := RouterEvaluationCase{ID: item.ID, ExpectedBrand: item.ExpectedBrand, ExpectedRole: item.ExpectedRole, ExpectedStatus: item.ExpectedStatus, ActualBrand: actual.Brand, ActualRole: actual.Role, ActualStatus: actual.Status, Confidence: actual.Confidence}
		caseReport.Passed, caseReport.Reason = routerCaseMatches(item, actual, len(result.Assessments) > 0)
		if caseReport.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
		report.Cases = append(report.Cases, caseReport)
		actualConfirmed := actual.ConfirmedRouter
		if item.ExpectedRouter {
			if actualConfirmed && (item.ExpectedBrand == "" || strings.EqualFold(item.ExpectedBrand, actual.Brand)) {
				truePositive++
			} else {
				falseNegative++
			}
		} else if actualConfirmed {
			falsePositive++
		}
		if !item.ExpectedRouter && item.ExpectedRole != "" {
			roleTotals[item.ExpectedRole]++
			if actualConfirmed {
				roleFalse[item.ExpectedRole]++
			}
		}
		if item.OUIOnly && actualConfirmed {
			report.OUIOnlyMisconfirmed++
		}
	}
	if denominator := truePositive + falsePositive; denominator > 0 {
		report.RouterPrecision = float64(truePositive) / float64(denominator)
	}
	if denominator := truePositive + falseNegative; denominator > 0 {
		report.RouterRecall = float64(truePositive) / float64(denominator)
	}
	for role, total := range roleTotals {
		report.RoleFalsePositiveRate[role] = float64(roleFalse[role]) / float64(total)
	}
	sort.Slice(report.Cases, func(i, j int) bool { return report.Cases[i].ID < report.Cases[j].ID })
	return report, nil
}

func routerCaseMatches(expected RouterGoldenCase, actual evidence.RouterAssessment, found bool) (bool, string) {
	if !found {
		if !expected.ExpectedRouter && expected.ExpectedStatus == "" {
			return true, ""
		}
		return false, "未生成路由观察结果"
	}
	if expected.ExpectedStatus != "" && expected.ExpectedStatus != actual.Status {
		return false, "置信度状态不匹配"
	}
	if expected.ExpectedBrand != "" && !strings.EqualFold(expected.ExpectedBrand, actual.Brand) {
		return false, "品牌不匹配"
	}
	if expected.ExpectedRole != "" && expected.ExpectedRole != actual.Role {
		return false, "角色不匹配"
	}
	if expected.ExpectedRouter != actual.ConfirmedRouter {
		return false, "确认结果不匹配"
	}
	return true, ""
}

func loadRouterGoldenEvents(path, kind string) ([]normalized.Event, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "normalized_jsonl", "jsonl":
		return readRouterNormalized(path)
	case "suricata_eve":
		return convertRouterInput(path, func(input io.Reader, output io.Writer) error {
			_, err := suricata.Convert(input, output, suricata.Options{SensorID: "router-golden"})
			return err
		})
	case "zeek_dir":
		return readRouterZeekDir(path)
	case "pcap":
		return readRouterPCAP(path)
	default:
		return nil, fmt.Errorf("unsupported router input_kind %q", kind)
	}
}

func readRouterNormalized(path string) ([]normalized.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return decodeRouterEvents(file)
}

func convertRouterInput(path string, convert func(io.Reader, io.Writer) error) ([]normalized.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var output bytes.Buffer
	if err := convert(file, &output); err != nil {
		return nil, err
	}
	return decodeRouterEvents(&output)
}

func readRouterZeekDir(path string) ([]normalized.Event, error) {
	kinds := []string{"dhcp", "software", "conn", "dns", "http", "ssl", "x509", "mdns", "nbns", "llmnr", "lldp", "ssdp", "ttl"}
	result := []normalized.Event{}
	for _, kind := range kinds {
		logPath := filepath.Join(path, kind+".log")
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			continue
		}
		events, err := convertRouterInput(logPath, func(input io.Reader, output io.Writer) error {
			_, convertErr := zeek.Convert(input, output, zeek.Options{SensorID: "router-golden", LogKind: kind})
			return convertErr
		})
		if err != nil {
			return nil, err
		}
		result = append(result, events...)
	}
	return result, nil
}

func readRouterPCAP(path string) ([]normalized.Event, error) {
	zeekBinary, err := exec.LookPath("zeek")
	if err != nil {
		return nil, fmt.Errorf("PCAP evaluation requires zeek: %w", err)
	}
	suricataBinary, err := exec.LookPath("suricata")
	if err != nil {
		return nil, fmt.Errorf("PCAP evaluation requires suricata: %w", err)
	}
	workDir, err := os.MkdirTemp("", "proxy-sentinel-router-pcap-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workDir)
	zeekDir := filepath.Join(workDir, "zeek")
	suricataDir := filepath.Join(workDir, "suricata")
	if err := os.MkdirAll(zeekDir, 0o750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(suricataDir, 0o750); err != nil {
		return nil, err
	}
	zeekCommand := exec.Command(zeekBinary, "-Cr", path, "LogAscii::use_json=T")
	zeekCommand.Dir = zeekDir
	if output, err := zeekCommand.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("run zeek PCAP replay: %w: %s", err, strings.TrimSpace(string(output)))
	}
	suricataCommand := exec.Command(suricataBinary, "-r", path, "-l", suricataDir)
	if output, err := suricataCommand.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("run suricata PCAP replay: %w: %s", err, strings.TrimSpace(string(output)))
	}
	events, err := readRouterZeekDir(zeekDir)
	if err != nil {
		return nil, err
	}
	evePath := filepath.Join(suricataDir, "eve.json")
	if _, err := os.Stat(evePath); err == nil {
		suricataEvents, convertErr := loadRouterGoldenEvents(evePath, "suricata_eve")
		if convertErr != nil {
			return nil, convertErr
		}
		events = append(events, suricataEvents...)
	}
	return events, nil
}

func decodeRouterEvents(reader io.Reader) ([]normalized.Event, error) {
	result := []normalized.Event{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var event normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, scanner.Err()
}

func routerEvaluationTime(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, raw)
}

func firstNonEmptyEvaluation(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
