package idevm

import "testing"

func TestNormalizeRegistrationSeparatesRegistrationFromObservation(t *testing.T) {
	fact, err := NormalizeRegistration(RegistrationRow{UserID: 42, UserRealName: "登记的打印机", MAC: "AA-BB-CC-DD-EE-FF", IP: "10.152.4.2", NASIP: "10.152.0.1", NetAccessMethod: 3, UserAvailable: 1, UserUpdateTime: 1793870000})
	if err != nil {
		t.Fatal(err)
	}
	if fact.SourceKey != "idevm:users:42" || fact.MAC != "aa:bb:cc:dd:ee:ff" || !fact.MatchableByMAC || fact.RegisteredIP != "10.152.4.2" || fact.AccessEnabled {
		t.Fatalf("incorrect registration fact: %+v", fact)
	}
}

func TestNormalizeRegistrationLeavesDot1XUnmatched(t *testing.T) {
	fact, err := NormalizeRegistration(RegistrationRow{UserID: 43, UserName: "dot1x-account", NetAccessMethod: 5})
	if err != nil {
		t.Fatal(err)
	}
	if fact.MatchableByMAC || fact.MAC != "" || fact.Name != "" {
		t.Fatalf("802.1X row must not be joined by an invented MAC: %+v", fact)
	}
}

func TestNormalizeRegistrationRejectsMalformedIdentity(t *testing.T) {
	for _, row := range []RegistrationRow{
		{NetAccessMethod: 1},
		{UserID: 1, NetAccessMethod: 9},
		{UserID: 1, NetAccessMethod: 1, MAC: "invalid"},
		{UserID: 1, NetAccessMethod: 3, IP: "bad-ip"},
	} {
		if _, err := NormalizeRegistration(row); err == nil {
			t.Fatalf("accepted invalid row: %+v", row)
		}
	}
}
