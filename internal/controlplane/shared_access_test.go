package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

type sharedTestReader struct {
	policySandboxReader
	windows []sharedaccess.Window
	err     error
}

func (r sharedTestReader) ListSharedAccessWindows(context.Context, time.Time, time.Time, int) ([]sharedaccess.Window, error) {
	return r.windows, r.err
}

// Isolated fixture telemetry explicitly covers each replay window; production
// capture diagnostics are never derived from the presence of traffic.
func (r sharedTestReader) ListIngestDiagnostics(_ context.Context, q store.Query) ([]ingest.Diagnostic, error) {
	items := []ingest.Diagnostic{}
	for _, w := range r.windows {
		if w.SensorID != q.SensorID {
			continue
		}
		for _, source := range w.Sources {
			items = append(items, ingest.Diagnostic{DiagnosticID: w.ID, Timestamp: w.To.Format(time.RFC3339Nano), SensorID: w.SensorID, Collector: ingest.Collector{Kind: source}, Stage: "capture_health", Type: "capture_coverage", Details: map[string]any{"schema_version": "capture-coverage/v1", "campus_id": w.CampusID, "access_domain": w.AccessDomain, "covered_from": w.From, "covered_to": w.To, "complete": true, "stopped": false, "query_truncated": false, "dropped_packets": int64(0)}})
		}
	}
	return items, nil
}
func TestSharedSimulationAndDeliveryGate(t *testing.T) {
	now := time.Now().UTC()
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	ss := []policy.Session{{ID: "session", AccountID: "a", EndpointID: "phone", IP: "192.0.2.1", CampusID: "c", AccessDomain: "nas", Source: "auth", SensorID: "auth", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-time.Minute), now}, HeartbeatSeconds: 60}}
	s.identitySources = []identitySourceRegistration{{IdentityScope: store.IdentityScope{Source: "auth", SensorID: "auth", CampusID: "c", AccessDomain: "nas"}, IntervalSeconds: 60}}
	s.sharedConfig = sharedaccess.Config{Version: "lab", FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "capture", Source: "suricata", CampusID: "c", AccessDomain: "nas"}}}
	window := sharedaccess.Window{ID: "shared-proof", RuleVersion: sharedaccess.RuleVersion, IP: "192.0.2.1", SensorID: "capture", CampusID: "c", AccessDomain: "nas", Sources: []string{"suricata"}, From: now.Add(-30 * time.Second), To: now, LastObservedAt: now, Complete: true, EventIDs: []string{"event"}, UAOS: []string{"Android", "Windows"}, TTLPaths: []string{"63", "127"}, TLSStacks: []string{"a", "b"}}
	addSharedRepeatedSamples(&window)
	reader := sharedTestReader{policySandboxReader: policySandboxReader{sessions: ss}, windows: []sharedaccess.Window{window}}
	s.reader = reader
	p := policy.Definition{ID: "shared", Name: "shared", Enabled: true, Mode: "observe", Trigger: "shared_access", WindowSeconds: 600}
	s.operations.doc.Policies[p.ID] = p
	for _, mode := range []string{"observe", "manual", "automatic"} {
		p.Mode = mode
		s.operations.doc.Policies[p.ID] = p
		body, _ := json.Marshal(map[string]any{"account_id": "a", "at": now})
		req := httptest.NewRequest("POST", "/api/v1/policies/shared/simulate", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		s.policySimulation(rec, req, "", p.ID)
		if rec.Code != 200 {
			t.Fatal(rec.Code, rec.Body.String())
		}
		var reply struct {
			Evaluations []struct {
				Input policy.Input          `json:"input"`
				Rows  []sharedaccess.Result `json:"shared_evaluation"`
			} `json:"evaluations"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		if len(reply.Evaluations) != 1 || len(reply.Evaluations[0].Rows) != 1 {
			t.Fatal(rec.Body.String())
		}
		in := reply.Evaluations[0].Input
		if mode == "observe" || mode == "manual" {
			if !in.Known || !in.Violated {
				t.Fatal(in)
			}
		} else if in.Known {
			t.Fatal("enforcement gate bypass", in)
		}
	}
	p.Mode = "observe"
	s.operations.doc.Policies[p.ID] = p
	s.processAccountPolicies(now)
	if len(s.operations.doc.PolicyExecutions) != 1 || len(s.operations.doc.Actions) != 0 {
		t.Fatal("cycle failed or produced action")
	}
	reader.err = errors.New("database unavailable")
	s.reader = reader
	s.processAccountPolicies(now.Add(time.Second))
	for _, ex := range s.operations.doc.PolicyExecutions {
		if ex.State == "recovered" {
			t.Fatal("database failure became recovery")
		}
	}
	ex := policy.Execution{Definition: policy.Definition{Trigger: "shared_access", Mode: "manual"}, Stages: []policy.StageState{{}}}
	s.createPolicyActionsLocked(&ex, 0, ss, now)
	if ex.Stages[0].Status != "blocked" || len(s.operations.doc.Actions) != 0 {
		t.Fatal("manual fanout bypass")
	}
	if err := s.validatePolicyDelivery(EnforcementAction{ActionType: "rate_limit", EvidenceIDs: []string{"shared-proof"}}); err == nil {
		t.Fatal("direct shared evidence action bypass")
	}
}

func TestSharedManualApprovalRevalidatesAndFansOut(t *testing.T) {
	for _, scenario := range []string{"fresh", "expired", "changed", "unknown_identity", "automatic"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now().UTC()
			s := NewServer(Options{ShadowDir: t.TempDir()})
			ss := []policy.Session{{ID: "s1", AccountID: "a", EndpointID: "phone", IP: "192.0.2.1", CampusID: "c", AccessDomain: "nas", Source: "auth", SensorID: "auth", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-time.Minute), now}, HeartbeatSeconds: 60}}
			second := ss[0]
			second.ID, second.IP, second.EndpointID = "s2", "192.0.2.2", "laptop"
			ss = append(ss, second)
			s.identitySources = []identitySourceRegistration{{IdentityScope: store.IdentityScope{Source: "auth", SensorID: "auth", CampusID: "c", AccessDomain: "nas"}, IntervalSeconds: 60}}
			s.sharedConfig = sharedaccess.Config{Version: "lab", FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "capture", Source: "suricata", CampusID: "c", AccessDomain: "nas"}}}
			w := sharedaccess.Window{ID: "shared-proof", RuleVersion: sharedaccess.RuleVersion, IP: "192.0.2.1", SensorID: "capture", CampusID: "c", AccessDomain: "nas", Sources: []string{"suricata"}, From: now.Add(-30 * time.Second), To: now, LastObservedAt: now, Complete: true, EventIDs: []string{"event"}, UAOS: []string{"Android", "Windows"}, TTLPaths: []string{"63", "127"}, TLSStacks: []string{"a", "b"}}
			addSharedRepeatedSamples(&w)
			reader := sharedTestReader{policySandboxReader: policySandboxReader{sessions: ss}, windows: []sharedaccess.Window{w}}
			s.reader = reader
			p := policy.Definition{ID: "shared", Name: "shared", Enabled: true, Mode: "manual", Trigger: "shared_access", WindowSeconds: 600, Stages: []policy.Stage{{Action: "disconnect", ConnectorID: "c"}}}
			s.operations.doc.Policies[p.ID] = p
			s.operations.doc.Connectors["c"] = ActionConnector{ConnectorID: "c", Enabled: true, Mode: "active", ShadowReady: true, ActionMapping: map[string]string{"account_policy_v1": "supported", "session.disconnect": "disconnect"}}
			e := policy.Execution{ID: policy.StableID(p.ID, "a"), PolicyID: p.ID, AccountID: "a", Definition: p, State: "awaiting_approval", EvidenceIDs: []string{w.ID}, Stages: []policy.StageState{{Key: "stage", Status: "awaiting_approval"}}}
			s.operations.doc.PolicyExecutions[e.ID] = e
			preview, err := buildPolicyApprovalPreview(e, ss, now)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "expired":
				reader.windows = nil
			case "changed":
				reader.windows[0].ID = "shared-new"
			case "unknown_identity":
				reader.sessions = nil
			case "automatic":
				p.Mode = "automatic"
				s.operations.doc.Policies[p.ID] = p
			}
			s.reader = reader
			body, _ := json.Marshal(map[string]string{"fingerprint": preview.Fingerprint})
			approve := func() int {
				r := httptest.NewRequest("POST", "/api/v1/policy-executions/"+e.ID+"/approve", bytes.NewReader(body))
				out := httptest.NewRecorder()
				s.handlePolicyExecutionMutation(out, r, "/policy-executions/"+e.ID+"/approve")
				if scenario == "fresh" && out.Code != 200 {
					t.Log(out.Body.String())
				}
				return out.Code
			}
			code := approve()
			if scenario != "fresh" {
				if code != 409 || len(s.operations.doc.Actions) != 0 {
					t.Fatalf("invalid approval accepted: %d", code)
				}
				return
			}
			if code != 200 || len(s.operations.doc.Actions) != 2 {
				t.Fatalf("manual action not created: code %d actions %d", code, len(s.operations.doc.Actions))
			}
			if approve() != 409 || len(s.operations.doc.Actions) != 2 {
				t.Fatal("duplicate approval created actions")
			}
			for _, a := range s.operations.doc.Actions {
				if err = s.validatePolicyDelivery(a); err != nil {
					t.Fatal(err)
				}
			}
			reader.windows = nil
			s.reader = reader
			for _, a := range s.operations.doc.Actions {
				if s.validatePolicyDelivery(a) == nil {
					t.Fatal("expired evidence delivered")
				}
			}
		})
	}
}

func addSharedRepeatedSamples(w *sharedaccess.Window) {
	for family, values := range map[string][]string{"ua_os": w.UAOS, "ttl_path": w.TTLPaths, "tls_stack": w.TLSStacks, "dhcp_stack": w.DHCPProfiles} {
		for _, value := range values {
			for _, at := range []time.Time{w.From, w.From.Add(time.Second), w.To} {
				w.ObserveFeature(family, value, at)
			}
		}
	}
}

type sharedHealthMissingReader struct{ sharedTestReader }

func (r sharedHealthMissingReader) ListIngestDiagnostics(context.Context, store.Query) ([]ingest.Diagnostic, error) {
	return nil, nil
}
func TestSharedWindowsUnknownHealthBlocksWithoutMutatingCache(t *testing.T) {
	now := time.Now().UTC()
	window := sharedaccess.Window{ID: "cache", SensorID: "capture", CampusID: "office", AccessDomain: "lan", Sources: []string{"suricata"}, From: now.Add(-30 * time.Second), To: now, Complete: true}
	reader := sharedHealthMissingReader{sharedTestReader{windows: []sharedaccess.Window{window}}}
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.reader = reader
	s.sharedConfig = sharedaccess.Config{FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "capture", Source: "suricata", CampusID: "office", AccessDomain: "lan"}}}
	windows, err := s.sharedWindows(context.Background(), now)
	if err != nil || len(windows) != 1 || windows[0].Complete || len(windows[0].Conflicts) != 1 {
		t.Fatal(windows, err)
	}
	if !reader.windows[0].Complete || len(reader.windows[0].Conflicts) != 0 {
		t.Fatal("cached evidence mutated")
	}
}
