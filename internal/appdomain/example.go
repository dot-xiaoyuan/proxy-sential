package appdomain

import "time"

// ExampleBundle is a contract/replay fixture, not a measured production signature set.
func ExampleBundle(now time.Time) ([]byte, error) {
	c := Catalog{Applications: []Target{{ID: "wechat", Name: "微信", Category: "social"}, {ID: "wecom", Name: "企业微信", Category: "office"}, {ID: "douyin", Name: "抖音", Category: "video"}, {ID: "bilibili", Name: "哔哩哔哩", Category: "video"}, {ID: "qq", Name: "QQ", Category: "social"}, {ID: "tencent-video", Name: "腾讯视频", Category: "video"}}, Ecosystems: []Target{{ID: "tencent", Name: "腾讯服务", Category: "ecosystem"}}, Infrastructures: []Target{{ID: "shared-cdn", Name: "共享 CDN", Category: "infrastructure"}}}
	rules := []Rule{}
	for _, v := range []struct{ id, domain, kind string }{{"wechat", "weixin.qq.com", "application"}, {"wecom", "work.weixin.qq.com", "application"}, {"douyin", "douyin.com", "application"}, {"bilibili", "bilibili.com", "application"}, {"qq", "im.qq.com", "application"}, {"tencent-video", "video.qq.com", "application"}, {"tencent", "qq.com", "ecosystem"}, {"shared-cdn", "cdn.example.com", "infrastructure"}} {
		rules = append(rules, Rule{ID: "fixture-" + v.id, Domain: v.domain, MatchType: "suffix", TargetType: v.kind, TargetID: v.id, Confidence: .9, Source: "contract-fixture", SourceVersion: "1"})
	}
	return Build("contract-fixture-v1", c, rules, []Source{{Name: "contract-fixture", Version: "1", License: "internal-test-fixture"}}, map[string][]byte{"licenses/NOTICE.txt": []byte("Synthetic contract and replay fixture. Domain mappings are not a validated production signature library. Review against labeled traffic before production publication.")}, now)
}
