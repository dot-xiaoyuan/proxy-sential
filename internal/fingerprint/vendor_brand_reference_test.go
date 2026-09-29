package fingerprint

import "testing"

func TestMACVendorBrandReferences(t *testing.T) {
	for _, c := range []struct{ vendor, want string }{
		{"Huawei Technologies Co.,Ltd.", "Huawei"}, {"vivo Mobile Communication Co., Ltd.", "Vivo"},
		{"Guangdong OPPO Mobile Telecommunications Corp.,Ltd", "OPPO"}, {"Apple, Inc.", "Apple"},
		{"Intel Corporation", ""}, {"Realtek Semiconductor Corp.", ""}, {"VMware, Inc.", ""}, {"Parallels, Inc.", ""},
		{"Unknown vendor", ""}, {"HuaweiFake Company", ""},
	} {
		t.Run(c.vendor, func(t *testing.T) {
			got := MACVendorBrandReference("00:10:20:30:40:50", c.vendor, .9)
			if c.want == "" {
				if got != nil {
					t.Fatalf("component or unknown vendor became brand: %+v", got)
				}
				return
			}
			if got == nil || got.Brand != c.want || got.Confidence >= .8 || got.Vendor != c.vendor || got.Explanation == "" {
				t.Fatalf("reference=%+v", got)
			}
			for _, mac := range []string{"02:10:20:30:40:50", "", "bad"} {
				if MACVendorBrandReference(mac, c.vendor, .9) != nil {
					t.Fatal("random or missing MAC must not yield reference")
				}
			}
			if MACVendorBrandReference("00:10:20:30:40:50", c.vendor, .5) != nil {
				t.Fatal("weak manufacturer evidence must not yield reference")
			}
		})
	}
}
