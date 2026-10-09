package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/sharedaccess"
)

func TestSharedGatewayBridgePreservesIdentityAndExplainsAnchorPostgres(t *testing.T) {
	for _, mode := range []string{"ieee", "models", "other_endpoint", "unknown_endpoint", "unknown_anchor"} {
		t.Run(mode, func(t *testing.T) {
			s := routerProjectionPrivatePostgres(t)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Microsecond)
			original := routerProjectionFact(now)
			if err := s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: original.RuleVersion, Evidence: []evidence.RouterEvidence{original}}); err != nil {
				t.Fatal(err)
			}
			item := sharedaccess.BehaviorAssessment{ObservationID: "bridge-window", SensorID: "office", IP: original.IP, EndpointID: original.EndpointID, Status: "confirmed", Confidence: 90, CoverageState: "verified", StrongAnchor: "ieee1905_association", DeviceLowerBound: 2, SignalGroups: []string{"confirmed_same_exit_endpoints", "ieee1905_association"}, FirstSeen: now.Add(-10 * time.Minute), LastSeen: now.Add(-time.Minute), WindowStart: now.Add(-10 * time.Minute), WindowEnd: now, EventIDs: []string{"association-a", "association-b"}}
			switch mode {
			case "models":
				item.StrongAnchor = "coexisting_device_models"
				item.SignalGroups = []string{"coexisting_device_models", "tcp_stack"}
			case "other_endpoint":
				item.EndpointID = "mac:02:00:00:00:00:aa"
			case "unknown_endpoint":
				item.EndpointID = ""
			case "unknown_anchor":
				item.StrongAnchor = "unsupported-anchor"
			}
			if mode == "other_endpoint" || mode == "unknown_endpoint" {
				router, err := s.sharedBehaviorRouter(ctx, item.EndpointID, item.IP, item.LastSeen)
				if err != nil {
					t.Fatal(err)
				}
				if router.Brand != "" || router.Role != "" {
					t.Errorf("IP reuse inherited unrelated hardware: %+v", router)
				}
			}
			if err := s.writeSharedGatewayRouterEvidence(ctx, item); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := s.pg.db.QueryRow(`SELECT count(*) FROM router_evidence_facts WHERE source_family='shared_gateway_behavior'`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if mode == "unknown_anchor" {
				if count != 0 {
					t.Fatalf("unsupported anchor created a gateway fact: %d", count)
				}
				return
			}
			if count != 1 {
				t.Fatalf("gateway fact count=%d", count)
			}
			var assessment, endpoint, brand, explanation string
			if err := s.pg.db.QueryRow(`SELECT assessment_id,endpoint_id,COALESCE(data->>'brand',''),data->>'explanation' FROM router_evidence_facts WHERE source_family='shared_gateway_behavior'`).Scan(&assessment, &endpoint, &brand, &explanation); err != nil {
				t.Fatal(err)
			}
			if mode == "other_endpoint" || mode == "unknown_endpoint" {
				if assessment == original.AssessmentID || endpoint != item.EndpointID || brand != "" {
					t.Fatalf("shared behavior attached to previous IP owner's hardware: assessment=%s endpoint=%s brand=%s", assessment, endpoint, brand)
				}
			}
			if mode == "models" {
				if !strings.Contains(explanation, "型号") || !strings.Contains(explanation, "协议栈") {
					t.Fatalf("missing model/stack basis: %s", explanation)
				}
			} else if !strings.Contains(explanation, "IEEE 1905") || strings.Contains(explanation, "协议栈") {
				t.Fatalf("association explanation invented protocol-stack proof: %s", explanation)
			}
		})
	}
}
