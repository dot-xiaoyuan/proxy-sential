package devicesignal

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

const verifiedSADPSample = `<ProbeMatch><MAC>08-54-11-13-c1-84</MAC><IPv4Address>10.126.253.1</IPv4Address><DeviceDescription>DS-K1T6QT-F72M</DeviceDescription><DeviceType>852122</DeviceType><Types>inquiry</Types></ProbeMatch>`

func sadpFrame(body, sourceMAC string, vlan bool) []byte {
	mac, _ := net.ParseMAC(sourceMAC)
	header := 14
	if vlan {
		header += 4
	}
	frame := make([]byte, header+20+8+len(body))
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], mac)
	if vlan {
		frame[12], frame[13], frame[14], frame[15], frame[16], frame[17] = 0x81, 0, 0, 17, 0x08, 0
	} else {
		frame[12], frame[13] = 0x08, 0
	}
	ip := frame[header : header+20]
	ip[0], ip[9] = 0x45, 17
	copy(ip[12:16], []byte{10, 126, 253, 1})
	copy(ip[16:20], []byte{239, 255, 255, 250})
	udp := frame[header+20 : header+28]
	udp[0], udp[1], udp[2], udp[3] = 0x90, 0x9c, 0x90, 0x9c
	copy(frame[header+28:], body)
	return frame
}

func TestSADPVerifiedSampleAndIdentityConflicts(t *testing.T) {
	direct, ok := parseControlFrame(sadpFrame(verifiedSADPSample, "08:54:11:13:c1:84", true))
	if !ok || direct.Kind != "sadp" || direct.IP != "10.126.253.1" || direct.MAC != "08:54:11:13:c1:84" || direct.VLAN != 17 || direct.Payload["product_model"] != "DS-K1T6QT-F72M" || direct.Payload["identity_status"] != "direct_l2" {
		t.Fatalf("verified SADP sample not attributed: ok=%t signal=%+v", ok, direct)
	}
	if _, exists := direct.Payload["device_type"]; exists {
		t.Fatalf("numeric SADP DeviceType was treated as a product class: %+v", direct.Payload)
	}
	mismatch, ok := parseControlFrame(sadpFrame(verifiedSADPSample, "00:11:22:33:44:55", false))
	if !ok || mismatch.MAC != "" || mismatch.Payload["identity_status"] != "l2_mismatch" {
		t.Fatalf("mismatched source MAC became identity: ok=%t signal=%+v", ok, mismatch)
	}
	ipMismatch := strings.Replace(verifiedSADPSample, "10.126.253.1", "10.126.253.2", 1)
	conflict, ok := parseControlFrame(sadpFrame(ipMismatch, "08:54:11:13:c1:84", false))
	if !ok || conflict.MAC != "" || conflict.Payload["identity_status"] != "ip_mismatch" {
		t.Fatalf("mismatched claimed IP became identity: ok=%t signal=%+v", ok, conflict)
	}
}

func TestSADPRejectsQueriesMalformedAndOversizedXML(t *testing.T) {
	for _, body := range []string{
		`<Probe><DeviceDescription>DS-K1T6QT-F72M</DeviceDescription></Probe>`,
		`<ProbeMatch><MAC>08-54-11-13-c1-84</MAC>`,
		strings.Repeat("x", 8193),
	} {
		if signal, ok := parseControlFrame(sadpFrame(body, "08:54:11:13:c1:84", false)); ok {
			t.Fatalf("invalid SADP emitted: %+v", signal)
		}
	}
	collision := sadpFrame(verifiedSADPSample, "08:54:11:13:c1:84", false)
	collision[34], collision[35] = 0x30, 0x39 // client source port 12345
	if signal, ok := parseControlFrame(collision); ok {
		t.Fatalf("traffic to UDP 37020 became a device response: %+v", signal)
	}
}

func TestSADPSuppressesDuplicatesWithoutSavingSensitiveFields(t *testing.T) {
	withSerial := strings.Replace(verifiedSADPSample, "</ProbeMatch>", "<SerialNO>private-serial</SerialNO></ProbeMatch>", 1)
	signal, ok := parseControlFrame(sadpFrame(withSerial, "08:54:11:13:c1:84", false))
	if !ok {
		t.Fatal("SADP response was rejected")
	}
	for _, value := range signal.Payload {
		if strings.Contains(strings.ToLower(fmt.Sprint(value)), "private-serial") {
			t.Fatalf("SADP serial leaked into normalized signal: %+v", signal.Payload)
		}
	}
	at := time.Now().UTC()
	tracker := newStateChangeTracker[string](5 * time.Minute)
	values := map[string]controlSignal{signal.key(): signal}
	if len(selectControls(tracker, at, values)) != 1 || len(selectControls(tracker, at.Add(time.Second), values)) != 0 {
		t.Fatal("duplicate SADP response was emitted repeatedly")
	}
}
