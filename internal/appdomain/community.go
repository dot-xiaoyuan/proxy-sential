package appdomain

import "time"

const communitySourceVersion = "20260922112956"

const v2flyMITLicense = `MIT License

Copyright (c) 2018-2019 V2Ray

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

// CommunityStarterBundle contains a deliberately small, high-precision set of
// application roots. Douyin, Bilibili and Amap rules are reviewed from an
// immutable V2Fly release. Tencent rules are separately marked as local
// reviewed overrides so their provenance is not overstated. The bundle excludes
// category/geolocation lists, shared CDNs, generic vendor roots and heuristic
// keyword rules. Local connectivity-check names are classified as infrastructure
// so they improve accounting without pretending to be apps.
func CommunityStarterBundle(now time.Time) ([]byte, error) {
	catalog := Catalog{
		Applications: []Target{
			{ID: "wechat", Name: "微信", Category: "social", Vendor: "Tencent"},
			{ID: "wecom", Name: "企业微信", Category: "office", Vendor: "Tencent"},
			{ID: "douyin", Name: "抖音", Category: "video", Vendor: "ByteDance"},
			{ID: "bilibili", Name: "哔哩哔哩", Category: "video", Vendor: "Bilibili"},
			{ID: "amap", Name: "高德地图", Category: "navigation", Vendor: "Alibaba"},
			{ID: "qq", Name: "QQ", Category: "social", Vendor: "Tencent"},
			{ID: "tencent-video", Name: "腾讯视频", Category: "video", Vendor: "Tencent"},
		},
		Ecosystems: []Target{{ID: "tencent", Name: "腾讯服务", Category: "ecosystem", Vendor: "Tencent"}},
		Infrastructures: []Target{
			{ID: "device-connectivity-check", Name: "终端联网探测", Category: "infrastructure"},
		},
	}

	type reviewedRule struct {
		id, domain, targetType, targetID, source, sourceVersion string
		confidence                                              float64
	}
	reviewed := []reviewedRule{
		{"wechat-weixin", "weixin.com", "application", "wechat", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"wechat-weixin-qq", "weixin.qq.com", "application", "wechat", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"wechat-service", "servicewechat.com", "application", "wechat", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"wechat-global", "wechat.com", "application", "wechat", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"wechat-pay", "wechatpay.com", "application", "wechat", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"wechat-bridge", "weixinbridge.com", "application", "wechat", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"wechat-sxy", "weixinsxy.com", "application", "wechat", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"wecom", "work.weixin.qq.com", "application", "wecom", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"douyin-amemv", "amemv.com", "application", "douyin", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"douyin-main", "douyin.com", "application", "douyin", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"douyin-cdn", "douyincdn.com", "application", "douyin", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"douyin-picture", "douyinpic.com", "application", "douyin", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"douyin-static", "douyinstatic.com", "application", "douyin", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"douyin-video", "douyinvod.com", "application", "douyin", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"douyin-client", "iesdouyin.com", "application", "douyin", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"douyin-commerce", "douyinec.com", "application", "douyin", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"douyin-open", "open-douyin.com", "application", "douyin", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"bilibili-main", "bilibili.com", "application", "bilibili", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"bilibili-video", "bilivideo.com", "application", "bilibili", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"bilibili-api", "biliapi.com", "application", "bilibili", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"bilibili-api-net", "biliapi.net", "application", "bilibili", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"bilibili-short", "b23.tv", "application", "bilibili", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"bilibili-acg", "acgvideo.com", "application", "bilibili", "v2fly/domain-list-community", communitySourceVersion, .92},
		{"amap-main", "amap.com", "application", "amap", "v2fly/domain-list-community", communitySourceVersion, .90},
		{"amap-net", "amap.net", "application", "amap", "v2fly/domain-list-community", communitySourceVersion, .90},
		{"amap-auto", "amapauto.com", "application", "amap", "v2fly/domain-list-community", communitySourceVersion, .90},
		{"amap-autonavi", "autonavi.com", "application", "amap", "v2fly/domain-list-community", communitySourceVersion, .90},
		{"amap-gaode", "gaode.com", "application", "amap", "v2fly/domain-list-community", communitySourceVersion, .90},
		{"qq-im", "im.qq.com", "application", "qq", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"tencent-video", "video.qq.com", "application", "tencent-video", "proxy-sentinel-reviewed-overrides", "2026-09-28", .92},
		{"tencent-ecosystem", "qq.com", "ecosystem", "tencent", "proxy-sentinel-reviewed-overrides", "2026-09-28", .80},
		{"connect-vivo", "connectivitycheck.vivo.com.cn", "infrastructure", "device-connectivity-check", "proxy-sentinel-observed-infrastructure", "2026-09-28", .99},
		{"connect-vivo-wifi", "wifi.vivo.com.cn", "infrastructure", "device-connectivity-check", "proxy-sentinel-observed-infrastructure", "2026-09-28", .99},
		{"connect-vivo-wf", "wf.vivo.com.cn", "infrastructure", "device-connectivity-check", "proxy-sentinel-observed-infrastructure", "2026-09-28", .99},
		{"connect-huawei-platform", "connectivitycheck.platform.hicloud.com", "infrastructure", "device-connectivity-check", "proxy-sentinel-observed-infrastructure", "2026-09-28", .99},
		{"connect-huawei-cbg", "connectivitycheck.cbg-app.huawei.com", "infrastructure", "device-connectivity-check", "proxy-sentinel-observed-infrastructure", "2026-09-28", .99},
		{"connect-microsoft", "www.msftconnecttest.com", "infrastructure", "device-connectivity-check", "proxy-sentinel-observed-infrastructure", "2026-09-28", .99},
		{"connect-apple", "captive.apple.com", "infrastructure", "device-connectivity-check", "proxy-sentinel-observed-infrastructure", "2026-09-28", .99},
	}
	rules := make([]Rule, 0, len(reviewed))
	for _, item := range reviewed {
		rules = append(rules, Rule{ID: "community-" + item.id, Domain: item.domain, MatchType: "suffix", TargetType: item.targetType, TargetID: item.targetID, Confidence: item.confidence, Source: item.source, SourceVersion: item.sourceVersion})
	}
	sources := []Source{
		{Name: "v2fly/domain-list-community", Version: communitySourceVersion, License: "MIT"},
		{Name: "proxy-sentinel-reviewed-overrides", Version: "2026-09-28", License: "internal-curation-notice"},
		{Name: "proxy-sentinel-observed-infrastructure", Version: "2026-09-28", License: "internal-curation-notice"},
	}
	licenses := map[string][]byte{
		"licenses/v2fly-domain-list-community-MIT.txt": []byte(v2flyMITLicense),
		"licenses/proxy-sentinel-curation-NOTICE.txt":  []byte("Tencent application roots are manually reviewed, test-only classification overrides. Connectivity-check rules are narrowly scoped infrastructure classifications reviewed from the NCU test mirror on 2026-09-28. Neither source is sufficient application-use or enforcement evidence without labeled replay and independent corroboration."),
	}
	return Build("community-ncu-20260922-v1", catalog, rules, sources, licenses, now)
}
