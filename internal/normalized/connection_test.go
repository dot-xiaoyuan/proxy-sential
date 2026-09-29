package normalized

import "testing"

func TestConnectionIdentityIsolation(t *testing.T) {
	a := ConnectionID("s", "suricata", "boot1", "18446744073709551615")
	if a == "" || a != ConnectionID("s", "suricata", "boot1", "18446744073709551615") {
		t.Fatal("not stable")
	}
	for _, b := range []string{ConnectionID("s", "suricata", "boot2", "18446744073709551615"), ConnectionID("s2", "suricata", "boot1", "18446744073709551615"), ConnectionID("s", "zeek", "boot1", "18446744073709551615")} {
		if b == a {
			t.Fatal("identity collision")
		}
	}
	if ConnectionID("s", "suricata", "", "1") != "" {
		t.Fatal("guessed missing instance")
	}
}
