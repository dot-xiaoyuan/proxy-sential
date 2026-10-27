package controlplane

import (
	"context"
	"fmt"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/netscan"
	"proxy-sentinel/internal/store"
)

type internalScanStore interface {
	ListInternalScanRules(context.Context) ([]store.InternalScanRule, []netscan.Zone, error)
	ListInternalScanAttempts(context.Context, time.Time, []string, int) ([]netscan.Attempt, error)
	WriteInternalScanFindings(context.Context, []netscan.Finding) error
	WriteInternalScanRun(context.Context, time.Time, string, string, int, int) error
	WriteEvidence(context.Context, []evidence.Evidence) error
}

func (s *Server) startInternalScanWorker() {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			s.processInternalScans(time.Now().UTC())
			<-ticker.C
		}
	}()
}

func (s *Server) processInternalScans(now time.Time) {
	reader, ok := s.reader.(internalScanStore)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rules, zones, err := reader.ListInternalScanRules(ctx)
	if err != nil {
		_ = reader.WriteInternalScanRun(ctx, now, "incomplete", err.Error(), 0, 0)
		return
	}
	if len(rules) == 0 {
		return
	}
	if len(zones) == 0 {
		_ = reader.WriteInternalScanRun(ctx, now, "incomplete", "no enabled network zones", 0, 0)
		return
	}
	for _, rule := range rules {
		found := false
		for _, zone := range zones {
			if zone.CampusID == rule.CampusID {
				found = true
				break
			}
		}
		if !found {
			_ = reader.WriteInternalScanRun(ctx, now, "incomplete", "enabled campus has no configured network zone: "+rule.CampusID, 0, 0)
			return
		}
	}
	var campuses []string
	for _, rule := range rules {
		campuses = append(campuses, rule.CampusID)
	}
	attempts, err := reader.ListInternalScanAttempts(ctx, now.Add(-10*time.Minute), campuses, 200000)
	if err != nil {
		_ = reader.WriteInternalScanRun(ctx, now, "incomplete", err.Error(), 0, 0)
		return
	}
	if len(attempts) == 0 {
		_ = reader.WriteInternalScanRun(ctx, now, "incomplete", "no flow events in window", 0, 0)
		return
	}
	var findings []netscan.Finding
	for _, rule := range rules {
		var scoped []netscan.Attempt
		for _, a := range attempts {
			if a.CampusID == rule.CampusID {
				scoped = append(scoped, a)
			}
		}
		findings = append(findings, netscan.Evaluate(rule.Config, zones, scoped, now)...)
	}
	if len(findings) == 0 {
		_ = reader.WriteInternalScanRun(ctx, now, "complete", "", len(attempts), 0)
		return
	}
	if err := reader.WriteInternalScanFindings(ctx, findings); err != nil {
		_ = reader.WriteInternalScanRun(ctx, now, "incomplete", err.Error(), len(attempts), 0)
		return
	}
	items := make([]evidence.Evidence, 0, len(findings))
	for _, f := range findings {
		samples := append([]string{}, f.EventIDs...)
		if len(samples) > 10 {
			samples = samples[:10]
		}
		samples = append(samples, fmt.Sprintf("zones=%d", len(f.ZoneIDs)), fmt.Sprintf("failed=%d/%d", f.Failed, f.Attempts))
		reason := fmt.Sprintf("%d 分钟内探测 %d 个内网网段、%d 个目标，%d 次连接中明确失败 %d 次；疑似内网探测，不能据此认定终端中毒", int(f.WindowEnd.Sub(f.WindowStart).Minutes()), len(f.ZoneIDs), f.UniqueDestinations, f.Attempts, f.Failed)
		items = append(items, evidence.Evidence{EvidenceID: store.InternalScanFindingID(f), IP: f.SourceIP, Type: string(f.Mode), Window: f.WindowStart.Format(time.RFC3339) + "~" + f.WindowEnd.Format(time.RFC3339), Score: 25, Confidence: 0.65, Severity: "medium", Reason: reason, Samples: samples, CreatedAt: f.WindowEnd.Format(time.RFC3339)})
	}
	if err := reader.WriteEvidence(ctx, items); err != nil {
		_ = reader.WriteInternalScanRun(ctx, now, "incomplete", err.Error(), len(attempts), len(findings))
		return
	}
	_ = reader.WriteInternalScanRun(ctx, now, "complete", "", len(attempts), len(findings))
}
