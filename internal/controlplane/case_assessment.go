package controlplane

import (
	"context"
	"encoding/json"
	"proxy-sentinel/internal/risk"
	"time"
)

// A human edit or retained investigation is not a fresh detection. This is a
// response projection only; scores, evidence and human workflow stay intact.
func projectCaseAssessment(item RiskCase, snapshot *risk.Snapshot, now time.Time) RiskCase {
	item.AssessmentCurrent = false
	item.AssessmentUpdatedAt, item.AssessmentWindow = "", ""
	if snapshot == nil || snapshot.IP != item.IP || snapshot.Score != item.RiskScore || snapshot.Confidence != item.RiskConfidence {
		return item
	}
	level := snapshot.Level
	if level == "confirmed" {
		level = "high"
	}
	if level != item.AssessmentLevel || snapshot.AccountID != item.AccountID || snapshot.EndpointID != item.EndpointID {
		return item
	}
	if snapshot.SubjectType != "" && snapshot.SubjectType != "ip" && snapshot.SubjectType != "account" && snapshot.SubjectType != "endpoint" {
		return item
	}
	if snapshot.SubjectType != "" && snapshot.SubjectID == "" {
		return item
	}
	if snapshot.SubjectType == "account" && snapshot.SubjectID != item.AccountID || snapshot.SubjectType == "endpoint" && snapshot.SubjectID != item.EndpointID || snapshot.SubjectType == "ip" && snapshot.SubjectID != item.IP {
		return item
	}
	switch item.SubjectType {
	case "": // Legacy file cases predate explicit subjects.
	case "ip":
		if item.SubjectID != item.IP {
			return item
		}
	case "account":
		if item.SubjectID == "" || item.SubjectID != item.AccountID || snapshot.SubjectType != "account" || snapshot.SubjectID != item.SubjectID {
			return item
		}
	case "endpoint":
		if item.SubjectID == "" || item.SubjectID != item.EndpointID || snapshot.SubjectType != "endpoint" || snapshot.SubjectID != item.SubjectID {
			return item
		}
	default:
		return item
	}
	item.AssessmentUpdatedAt, item.AssessmentWindow = snapshot.UpdatedAt, snapshot.Window
	item.AssessmentCurrent = item.Status != "closed" && item.Status != "resolved" && currentRiskObservation(snapshot.UpdatedAt, snapshot.Window, now)
	return item
}

// Bound cases require the corresponding subject snapshot. The IP table does
// not carry account/endpoint ownership, so it cannot renew a bound case. These
// are primary-key lookups in the same transaction, without history aggregation.
const caseAssessmentProjection = `to_jsonb(c)||jsonb_build_object('ip',coalesce(host(c.ip),''),'nas_ip',coalesce(host(c.nas_ip),''),'_current_risk',CASE
 WHEN c.subject_type IN ('account','endpoint') THEN (SELECT to_jsonb(rs)||jsonb_build_object('ip',coalesce(host(rs.ip),'')) FROM subject_risk_snapshots rs WHERE rs.subject_type=c.subject_type AND rs.subject_id=c.subject_id)
 WHEN coalesce(c.endpoint_id,'')<>'' THEN (SELECT to_jsonb(rs)||jsonb_build_object('ip',coalesce(host(rs.ip),'')) FROM subject_risk_snapshots rs WHERE rs.subject_type='endpoint' AND rs.subject_id=c.endpoint_id)
 WHEN coalesce(c.account_id,'')<>'' THEN (SELECT to_jsonb(rs)||jsonb_build_object('ip',coalesce(host(rs.ip),'')) FROM subject_risk_snapshots rs WHERE rs.subject_type='account' AND rs.subject_id=c.account_id)
 ELSE (SELECT to_jsonb(rs)||jsonb_build_object('ip',host(rs.ip)) FROM risk_snapshots rs WHERE rs.ip=c.ip) END)`

func decodeCaseAssessment(raw []byte) (RiskCase, error) {
	var doc struct {
		RiskCase
		CurrentRisk *risk.Snapshot `json:"_current_risk"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return RiskCase{}, err
	}
	if kind := riskKindForRuleset(doc.RulesetVersion); kind != "" {
		doc.RiskKind = kind
		doc.AssessmentCurrent = doc.Status != "closed" && doc.Status != "resolved"
		doc.AssessmentUpdatedAt = doc.LastSeen
		return doc.RiskCase, nil
	}
	return projectCaseAssessment(doc.RiskCase, doc.CurrentRisk, time.Now().UTC()), nil
}

func (s *Server) projectFileCaseAssessment(item RiskCase) RiskCase {
	if kind := riskKindForRuleset(item.RulesetVersion); kind != "" {
		item.RiskKind = kind
		item.AssessmentCurrent = item.Status != "closed" && item.Status != "resolved"
		item.AssessmentUpdatedAt = item.LastSeen
		return item
	}
	if s.reader == nil {
		return projectCaseAssessment(item, nil, time.Now().UTC())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := s.reader.GetIPRisk(ctx, item.IP)
	if err != nil {
		return projectCaseAssessment(item, nil, time.Now().UTC())
	}
	return projectCaseAssessment(item, &snapshot, time.Now().UTC())
}

// PostgreSQL mutations already loaded a matching snapshot in their transaction.
// Recheck its timestamp and the resulting status before returning the update.
func (s *Server) projectMutatedCaseAssessment(item RiskCase) RiskCase {
	if s.operations.db == nil {
		return s.projectFileCaseAssessment(item)
	}
	item.AssessmentCurrent = item.Status != "closed" && item.Status != "resolved" && currentRiskObservation(item.AssessmentUpdatedAt, item.AssessmentWindow, time.Now().UTC())
	return item
}
