package discovery

import (
	"testing"

	"proxy-sentinel/internal/fingerprint"
)

func TestClassifyMirrorMACsKeepsDisjointBuckets(t *testing.T) {
	library := fingerprint.MustLoad("coverage-test", []byte("Assignment,Organization Name\n001122,Registered Vendor\n"), []byte("[]"))
	matched, local, unmatched := classifyMirrorMACs(library, []string{
		"00:11:22:33:44:55", "02:11:22:33:44:55", "10:34:56:78:9a:bc",
	})
	if matched != 1 || local != 1 || unmatched != 1 {
		t.Fatalf("MAC cohorts overlap or omit entries: oui=%d local=%d other=%d", matched, local, unmatched)
	}
}
