package appdomain

import (
	"testing"
	"time"
)

func TestCommunityStarterBundleHighPrecisionMatches(t *testing.T) {
	raw, err := CommunityStarterBundle(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"shortcloud.weixin.com":                  "wechat",
		"webcast-core-m.amemv.com":               "douyin",
		"p11.douyinpic.com":                      "douyin",
		"httpdns.bilivideo.com":                  "bilibili",
		"aps.amap.com":                           "amap",
		"connectivitycheck.cbg-app.huawei.com":   "device-connectivity-check",
		"connectivitycheck.platform.hicloud.com": "device-connectivity-check",
	} {
		if got := bundle.Match(host); got.TargetID != want {
			t.Fatalf("match %s=%+v want=%s", host, got, want)
		}
	}
	for _, host := range []string{"magicneko.com", "zijieapi.com", "qpic.cn", "huawei.com", "cloudfront.net"} {
		if got := bundle.Match(host); got.TargetID != "" {
			t.Fatalf("broad or unrelated host %s matched %+v", host, got)
		}
	}
	if got := bundle.Match("assets.biligame.net"); got.TargetID != "" {
		t.Fatalf("game ecosystem host must not be promoted to the Bilibili video app: %+v", got)
	}
	if source := bundle.Match("shortcloud.weixin.com").Source; source != "proxy-sentinel-reviewed-overrides" {
		t.Fatalf("wechat provenance=%q want reviewed override", source)
	}
	if source := bundle.Match("webcast-core-m.amemv.com").Source; source != "v2fly/domain-list-community" {
		t.Fatalf("douyin provenance=%q want immutable community source", source)
	}
}
