package evaluation

import (
	"proxy-sentinel/internal/risk"
	"strings"
	"testing"
)

func TestCompareClassifiesNewOldDifferences(t *testing.T) {
	report := Compare(risk.BatchResult{Snapshots: []risk.Snapshot{{IP: "10.0.0.1", Level: "high", Score: 70}, {IP: "10.0.0.2", Level: "suspicious", Score: 45}}}, []LegacyAssessment{{IP: "10.0.0.1", Level: "confirmed", Score: 90}, {IP: "10.0.0.3", Detected: true}})
	if report.LevelChanged != 1 || report.CurrentOnly != 1 || report.LegacyOnly != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
}
func TestReadLegacyCSV(t *testing.T) {
	items, err := ReadLegacy(strings.NewReader("ip,level,score\n10.0.0.1,high,70\n"))
	if err != nil || len(items) != 1 || items[0].Score != 70 {
		t.Fatalf("unexpected legacy data: %+v %v", items, err)
	}
}
