package appdomain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type Release struct {
	Version          string `json:"version"`
	CreatedAt        string `json:"created_at"`
	PublishedAt      string `json:"published_at"`
	OrderingBasis    string `json:"ordering_basis"`
	SHA256           string `json:"sha256"`
	Size             int    `json:"size"`
	RuleCount        int    `json:"rule_count"`
	ApplicationCount int    `json:"application_count"`
}

func selectRelease(raw []byte) (Release, error) {
	var response struct {
		Success bool `json:"success"`
		Data    struct {
			LatestVersion string    `json:"latest_version"`
			Releases      []Release `json:"releases"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || !response.Success {
		return Release{}, fmt.Errorf("特征库发布索引格式无效")
	}
	if len(response.Data.Releases) == 0 {
		return Release{}, fmt.Errorf("特征库尚未发布应用规则包")
	}
	seen := map[string]bool{}
	var latest Release
	var latestTime time.Time
	for _, r := range response.Data.Releases {
		created, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
		if err != nil || created.IsZero() {
			return Release{}, fmt.Errorf("规则包创建时间无效")
		}
		digest, err := hex.DecodeString(r.SHA256)
		if !safeVersion.MatchString(r.Version) || seen[r.Version] || err != nil || len(digest) != 32 || r.Size <= 0 || r.Size > MaxBundleBytes || r.RuleCount <= 0 || r.ApplicationCount < 0 {
			return Release{}, fmt.Errorf("规则包索引元数据无效")
		}
		seen[r.Version] = true
		orderingTime := created
		switch r.OrderingBasis {
		case "published_at":
			orderingTime, err = time.Parse(time.RFC3339Nano, r.PublishedAt)
			if err != nil || orderingTime.IsZero() {
				return Release{}, fmt.Errorf("规则包发布时间无效")
			}
		case "created_at_fallback":
			if r.PublishedAt != "" {
				return Release{}, fmt.Errorf("规则包排序依据冲突")
			}
		default:
			return Release{}, fmt.Errorf("规则包排序依据无效")
		}
		if latest.Version == "" || orderingTime.After(latestTime) || (orderingTime.Equal(latestTime) && r.Version > latest.Version) {
			latest = r
			latestTime = orderingTime
		}
	}
	if latest.Version != response.Data.LatestVersion {
		return Release{}, fmt.Errorf("特征库最新版本与发布时间不一致")
	}
	return latest, nil
}
