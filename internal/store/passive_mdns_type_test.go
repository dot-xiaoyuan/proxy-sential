package store

import "testing"

func TestPassiveModelDeviceType(t *testing.T) {
	for _, tc := range []struct{ model, text, want string }{
		{"iPhone14,2", "", "mobile"},
		{"iPad8,1", "", "tablet"},
		{"MacBookPro18,3", "", "desktop"},
		{"iMac21,1", "", "desktop"},
		{"AppleTV3,1", "", "media_device"},
		{"AudioAccessory5,1", "", "media_device"},
		{"", "packagename=com.tcl.MultiScreenInteraction_TV htv=1", "media_device"},
		{"", "deviceid=aa:bb", ""},
	} {
		if got := passiveModelDeviceType(tc.model, tc.text); got != tc.want {
			t.Fatalf("model=%q text=%q got %q want %q", tc.model, tc.text, got, tc.want)
		}
	}
}
