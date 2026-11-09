package store

import "testing"

func TestPassivePrinterTypeClassifiesScanningServices(t *testing.T) {
	for _, tc := range []struct {
		caps  []string
		value string
		want  string
	}{
		{[]string{"printing"}, "HP LaserJet MFP M227-M231", "printer"},
		{[]string{"scanning"}, "HP LaserJet MFP M227-M231", "printer"},
		{[]string{"scanning"}, "Canon scanner", "scanner"},
		{[]string{"scanning"}, "ty=Brother DCP", "scanner"},
		{[]string{"scanning"}, "unknown-device", ""},
		{[]string{"casting"}, "Apple TV", ""},
		{nil, "HP LaserJet", ""},
	} {
		if got := passivePrinterType(tc.caps, tc.value); got != tc.want {
			t.Fatalf("caps=%v value=%q => %q, want %q", tc.caps, tc.value, got, tc.want)
		}
	}
}
