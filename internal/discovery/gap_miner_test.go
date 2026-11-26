package discovery

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeGapOptionsBounds(t *testing.T) {
	got := NormalizeGapOptions(GapMineOptions{})
	if got.SensorID != "campus-204" || got.Window != 24*time.Hour || got.Top != 50 {
		t.Fatalf("unexpected defaults: %+v", got)
	}
	clamped := NormalizeGapOptions(GapMineOptions{SensorID: "campus-204", Window: 30 * 24 * time.Hour, Top: 999})
	if clamped.Window != 7*24*time.Hour || clamped.Top != 100 {
		t.Fatalf("expected upper bounds to clamp: %+v", clamped)
	}
	low := NormalizeGapOptions(GapMineOptions{SensorID: "campus-204", Window: 5 * time.Minute, Top: -1})
	if low.Window != time.Hour || low.Top != 50 {
		t.Fatalf("expected lower bounds to clamp: %+v", low)
	}
}

func TestRenderGapReportMarkdown(t *testing.T) {
	report := GapReport{
		SensorID:    "campus-204",
		Window:      "24h0m0s",
		GeneratedAt: "2026-11-26T07:00:00Z",
		Overlap: TwoListOverlap{
			TerminalMACs:      4200,
			DiscoveryMACs:     3800,
			OverlapMACs:       3600,
			TerminalOnlyMACs:  600,
			DiscoveryOnlyMACs: 200,
		},
		HardwareStatuses: []StatusCount{{Status: "identified", Count: 340, MACs: 338}},
		UnmatchedDHCP:    []FeatureGapItem{{Category: "dhcp", Value: "android-dhcp-14", Detail: "1,3,6,15", Entities: 420, Events: 1200}},
		MirrorPorts:      []PortGapItem{{Proto: "udp", Port: 37810, Annotation: CampusPortAnnotation("udp", 37810), SourceIPs: 18, Buckets: 90}},
		Warnings:         []string{"sample warning"},
	}
	md := RenderGapReportMarkdown(report)
	for _, want := range []string{
		"被动发现未识别特征摸底报告",
		"| 4200 | 3800 | 3600 | 600 | 200 |",
		"`android-dhcp-14`",
		"大华设备发现协议",
		"sample warning",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("rendered markdown missing %q:\n%s", want, md)
		}
	}
}
