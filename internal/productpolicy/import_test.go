package productpolicy

import (
	"testing"
	"time"
)

func TestBuildPreviewUsesLargestPositiveSessionLimitAndPreservesReferences(t *testing.T) {
	snapshot := Snapshot{Source: "office", Products: []Product{{ID: "p1", Name: "办公", ControlIDs: []string{"c1", "c2"}}}, Controls: []Control{{ID: "c1", Name: "一", MaxOnlineNum: 2, DisableProxy: 1}, {ID: "c2", Name: "二", MaxOnlineNum: 4, ProxyTimes: 3, Reference: map[string]string{"route_condition": "office"}}}}
	preview := BuildPreview(snapshot, "snap", "batch", time.Now())
	item := preview.Items[0]
	if item.Disposition != "direct" || item.Policy == nil || item.Policy.Limits.Sessions == nil || *item.Policy.Limits.Sessions != 4 || item.Policy.Mode != "observe" || !item.Policy.Enabled {
		t.Fatalf("unexpected conversion: %+v", item)
	}
	if len(item.Policy.Origin.ExternalPolicyIDs) != 2 || len(item.Policy.Origin.ReferenceFields) != 3 {
		t.Fatalf("source semantics not preserved: %+v", item.Policy.Origin)
	}
}

func TestBuildPreviewNeverApproximatesUnsupportedControl(t *testing.T) {
	snapshot := Snapshot{Source: "office", Products: []Product{{ID: "p1", Name: "办公", ControlIDs: []string{"c1"}}}, Controls: []Control{{ID: "c1", Name: "旧防代理", DisableProxy: 1, ProxyTimes: 3}}}
	preview := BuildPreview(snapshot, "snap", "batch", time.Now())
	if preview.Items[0].Disposition != "reference_only" || preview.Items[0].Policy != nil {
		t.Fatalf("unsupported semantics were approximated: %+v", preview.Items[0])
	}
}

func TestBuildPreviewKeepsDeviceQuotaSeparateFromSessionQuota(t *testing.T) {
	total := 2
	snapshot := Snapshot{Source: "office", Products: []Product{{ID: "p1", Name: "办公"}}, AntiProxyProfiles: []AntiProxyProfile{{ExternalID: "legacy", Name: "终端配额", TargetType: "product", TargetIDs: []string{"p1"}, Total: &total}}}
	preview := BuildPreview(snapshot, "snap", "batch", time.Now())
	policy := preview.Items[0].Policy
	if policy == nil || policy.ID != "srun4k:office:product:p1:quota_exceeded" || policy.Trigger != "quota_exceeded" || policy.Limits.Sessions != nil || policy.Limits.Total == nil || *policy.Limits.Total != 2 {
		t.Fatalf("device and session quotas were conflated: %+v", policy)
	}
}

func TestBuildPreviewRequiresProductCatalogMatch(t *testing.T) {
	total := 2
	snapshot := Snapshot{Source: "office", AntiProxyProfiles: []AntiProxyProfile{{ExternalID: "legacy", Name: "终端配额", TargetType: "product", TargetIDs: []string{"missing"}, Total: &total}}}
	item := BuildPreview(snapshot, "snap", "batch", time.Now()).Items[0]
	if item.Disposition != "configuration_required" || item.Policy != nil || item.Reasons[0] != "product_missing" {
		t.Fatalf("missing product was silently imported: %+v", item)
	}
}

func TestBuildPreviewDoesNotImportExecutionActions(t *testing.T) {
	snapshot := Snapshot{Source: "office", Products: []Product{{ID: "p1", Name: "办公", ControlIDs: []string{"c1"}}}, Controls: []Control{{ID: "c1", Name: "在线数", MaxOnlineNum: 2}}}
	item := BuildPreview(snapshot, "snap", "batch", time.Now()).Items[0]
	if item.Policy == nil || item.Policy.Mode != "observe" || len(item.Policy.Stages) != 1 || item.Policy.Stages[0].Action != "record" || item.Policy.Stages[0].ConnectorID != "" {
		t.Fatalf("4K directory import must not manufacture an execution action: %+v", item.Policy)
	}
}
