package devicesignal

import "testing"

func TestSSDPAnnouncementResponseAndQueryRemainDistinct(t *testing.T) {
	for _, tc := range []struct {
		raw                                         string
		accepted, response, announcement, withdrawn bool
	}{
		{"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nNTS: ssdp:byebye\r\n", true, false, true, true},
		{"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n", true, false, true, false},
		{"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n", true, true, false, false},
		{"M-SEARCH * HTTP/1.1\r\nST: upnp:rootdevice\r\n", false, false, false, false},
	} {
		s, ok := parseSSDP(ethernetFrame{}, "10.0.0.2", "239.255.255.250", []byte(tc.raw))
		if ok != tc.accepted || ok && ((s.Payload["is_response"] == true) != tc.response || (s.Payload["is_announcement"] == true) != tc.announcement || (s.Payload["withdrawn"] == true) != tc.withdrawn) {
			t.Fatalf("announcement semantics: %+v %v", s, ok)
		}
	}
}
