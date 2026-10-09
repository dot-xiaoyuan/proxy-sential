package productpolicy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/policy"
)

const ConversionVersion = "srun4k-to-sentinel/v1"

type ConversionItem struct {
	ExternalType string             `json:"external_type"`
	ExternalID   string             `json:"external_id"`
	Name         string             `json:"name"`
	Disposition  string             `json:"disposition"`
	Reasons      []string           `json:"reasons"`
	Policy       *policy.Definition `json:"policy,omitempty"`
}

type Preview struct {
	SnapshotID string           `json:"snapshot_id"`
	Source     string           `json:"source"`
	Items      []ConversionItem `json:"items"`
	Summary    map[string]int   `json:"summary"`
}

func BuildPreview(snapshot Snapshot, snapshotID, batchID string, now time.Time) Preview {
	controls := map[string]Control{}
	products := map[string]bool{}
	for _, product := range snapshot.Products {
		products[product.ID] = true
	}
	for _, control := range snapshot.Controls {
		controls[control.ID] = control
	}
	result := Preview{SnapshotID: snapshotID, Source: snapshot.Source, Items: []ConversionItem{}, Summary: map[string]int{}}
	for _, product := range snapshot.Products {
		positiveMax := 0
		contributors := []string{}
		references := []string{}
		missing := []string{}
		for _, id := range product.ControlIDs {
			control, ok := controls[id]
			if !ok {
				missing = append(missing, id)
				continue
			}
			contributors = append(contributors, control.ID)
			if control.MaxOnlineNum > 0 {
				if control.MaxOnlineNum > positiveMax {
					positiveMax = control.MaxOnlineNum
				}
			}
			if control.DisableProxy > 0 {
				references = append(references, "disable_proxy")
			}
			if control.ProxyTimes > 0 {
				references = append(references, "proxy_times")
			}
			if control.ProxyDisableTime > 0 {
				references = append(references, "proxy_disable_time")
			}
			for field := range control.Reference {
				references = append(references, "source_field:"+field)
			}
		}
		sort.Strings(contributors)
		references = normalizedIDs(references)
		item := ConversionItem{ExternalType: "product", ExternalID: product.ID, Name: product.Name, Disposition: "reference_only", Reasons: []string{"positive_max_online_num_missing"}}
		if len(missing) > 0 {
			item.Disposition = "rejected"
			item.Reasons = []string{"referenced_control_missing"}
		} else if positiveMax > 0 {
			limit := positiveMax
			id := fmt.Sprintf("srun4k:%s:product:%s:session_quota_exceeded", snapshot.Source, product.ID)
			item.Disposition = "direct"
			item.Reasons = []string{"maximum_positive_max_online_num", "product_baseline_only"}
			if len(references) > 0 {
				item.Reasons = append(item.Reasons, "unsupported_fields_preserved_as_reference")
			}
			item.Policy = &policy.Definition{ID: id, Name: product.Name + "认证会话上限", Enabled: true, Priority: 0, Mode: "observe", Trigger: "session_quota_exceeded", Scope: policy.Scope{Products: []string{product.ID}}, Limits: policy.Limits{Sessions: &limit}, SustainSeconds: 0, WindowSeconds: 86400, RecoverySeconds: 0, CooldownSeconds: 0, Stages: []policy.Stage{{Action: "record", MinEpisodes: 1}}, Origin: &policy.Origin{Source: snapshot.Source, SnapshotID: snapshotID, ExternalProductID: product.ID, ExternalPolicyIDs: contributors, ConversionVersion: ConversionVersion, ImportBatchID: batchID, ReferenceFields: references}}
		}
		result.Items = append(result.Items, item)
		result.Summary[item.Disposition]++
	}
	for _, profile := range snapshot.AntiProxyProfiles {
		item := ConversionItem{ExternalType: "anti_proxy_profile", ExternalID: profile.ExternalID, Name: profile.Name, Disposition: "configuration_required", Reasons: append([]string{}, profile.Unsupported...)}
		missingProduct := false
		if profile.TargetType == "product" {
			for _, id := range profile.TargetIDs {
				missingProduct = missingProduct || !products[id]
			}
		}
		if missingProduct {
			item.Reasons = append(item.Reasons, "product_missing")
		} else if profile.Total != nil || profile.Mobile != nil || profile.PC != nil {
			id := fmt.Sprintf("srun4k:%s:%s:%s:quota_exceeded", snapshot.Source, profile.TargetType, profile.ExternalID)
			externalProductID := ""
			if profile.TargetType == "product" && len(profile.TargetIDs) == 1 {
				id = fmt.Sprintf("srun4k:%s:product:%s:quota_exceeded", snapshot.Source, profile.TargetIDs[0])
				externalProductID = profile.TargetIDs[0]
			}
			scope := policy.Scope{}
			if profile.TargetType == "product" {
				scope.Products = append([]string{}, profile.TargetIDs...)
			} else {
				scope.Groups = append([]string{}, profile.TargetIDs...)
			}
			item.Disposition = "direct"
			item.Policy = &policy.Definition{ID: id, Name: profile.Name, Enabled: true, Mode: "observe", Trigger: "quota_exceeded", Scope: scope, Limits: policy.Limits{Total: profile.Total, Mobile: profile.Mobile, PC: profile.PC}, WindowSeconds: 86400, CooldownSeconds: profile.CooldownSeconds, Stages: []policy.Stage{{Action: "record", MinEpisodes: 1}}, Origin: &policy.Origin{Source: snapshot.Source, SnapshotID: snapshotID, ExternalProductID: externalProductID, ExternalPolicyIDs: []string{profile.ExternalID}, ConversionVersion: ConversionVersion, ImportBatchID: batchID, ReferenceFields: append([]string{}, profile.Unsupported...)}}
		}
		if len(item.Reasons) == 0 {
			item.Reasons = []string{"device_quota_fields_missing"}
		}
		result.Items = append(result.Items, item)
		result.Summary[item.Disposition]++
	}
	sort.Slice(result.Items, func(i, j int) bool {
		return strings.Join([]string{result.Items[i].ExternalType, result.Items[i].ExternalID}, ":") < strings.Join([]string{result.Items[j].ExternalType, result.Items[j].ExternalID}, ":")
	})
	return result
}
