package zeek

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func identityPCAP(frames ...[]byte) []byte {
	b := new(bytes.Buffer)
	for _, value := range []any{uint32(0xa1b2c3d4), uint16(2), uint16(4), int32(0), uint32(0), uint32(65535), uint32(1)} {
		_ = binary.Write(b, binary.LittleEndian, value)
	}
	for i, frame := range frames {
		for _, value := range []uint32{1785232800, uint32(i * 1000), uint32(len(frame)), uint32(len(frame))} {
			_ = binary.Write(b, binary.LittleEndian, value)
		}
		b.Write(frame)
	}
	return b.Bytes()
}

func identityFrame(source, destination string, sport, dport uint16, payload []byte, tcp bool, seq, ack uint32, flags byte) []byte {
	l4 := make([]byte, 8)
	if tcp {
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint32(l4[4:], seq)
		binary.BigEndian.PutUint32(l4[8:], ack)
		l4[12], l4[13] = 0x50, flags
		binary.BigEndian.PutUint16(l4[14:], 65535)
	} else {
		binary.BigEndian.PutUint16(l4[4:], uint16(len(payload)+8))
	}
	binary.BigEndian.PutUint16(l4, sport)
	binary.BigEndian.PutUint16(l4[2:], dport)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	if tcp {
		ip[9] = 6
	}
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)+len(payload)))
	copy(ip[12:], net.ParseIP(source).To4())
	copy(ip[16:], net.ParseIP(destination).To4())
	eth := []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 8, 0}
	return append(append(append(eth, ip...), l4...), payload...)
}

func replayIdentityZeek(t *testing.T, pcap []byte, industrial bool) string {
	t.Helper()
	zeek, err := exec.LookPath("zeek")
	if err != nil {
		t.Skip("Zeek is not installed; adapter fixtures still run")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "response.pcap")
	if err := os.WriteFile(path, pcap, 0600); err != nil {
		t.Fatal(err)
	}
	root, _ := filepath.Abs("../../..")
	args := []string{"-C", "-r", path, filepath.Join(root, "assets/zeek/snmp-device-signals.zeek"), "ProxySentinelSNMP::enabled=T", "LogAscii::use_json=T"}
	var env []string
	if industrial {
		pluginRoot := os.Getenv("PROXY_SENTINEL_TEST_ICSNPP_ROOT")
		if pluginRoot == "" {
			t.Skip("set PROXY_SENTINEL_TEST_ICSNPP_ROOT to the locally built pinned parser")
		}
		zeekPath, err := exec.Command("zeek-config", "--zeekpath").Output()
		if err != nil {
			t.Fatal(err)
		}
		env = append(os.Environ(), "ZEEK_PLUGIN_PATH="+filepath.Join(pluginRoot, "plugins"), "ZEEKPATH="+strings.TrimSpace(string(zeekPath))+":"+filepath.Join(pluginRoot, "plugins/ICSNPP_Bacnet/scripts"))
		args = append(args, filepath.Join(root, "assets/zeek/passive-industrial-signals.zeek"))
	}
	cmd := exec.Command(zeek, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Zeek replay: %v\n%s", err, output)
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
		if strings.Contains(string(raw), "test-community-secret") || strings.Contains(string(raw), "password-secret") {
			t.Fatalf("credential persisted in %s", entry.Name())
		}
	}
	return dir
}

func readIdentityEvents(t *testing.T, dir, name, kind string) []normalized.Event {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	stats, err := Convert(bytes.NewReader(raw), &out, Options{SensorID: "replay", LogKind: kind})
	if err != nil || stats.Emitted == 0 {
		t.Fatalf("%s did not produce identity: %+v %v\n%s", kind, stats, err, raw)
	}
	var events []normalized.Event
	for _, row := range bytes.Split(bytes.TrimSpace(out.Bytes()), []byte{'\n'}) {
		var e normalized.Event
		if err := json.Unmarshal(row, &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	return events
}

func berIdentity(tag byte, data ...[]byte) []byte {
	body := bytes.Join(data, nil)
	out := []byte{tag}
	if len(body) < 128 {
		out = append(out, byte(len(body)))
	} else {
		out = append(out, 0x82, byte(len(body)>>8), byte(len(body)))
	}
	return append(out, body...)
}

func TestZeekSNMPResponsePCAP(t *testing.T) {
	// Synthetic BER packet replay. The response is the first packet in its
	// connection; this proves endpoint selection uses response direction, not
	// an assumption that the connection originator is a management client.
	descrOID := []byte{43, 6, 1, 2, 1, 1, 1, 0}
	objectOID := []byte{43, 6, 1, 2, 1, 1, 2, 0}
	bindings := berIdentity(0x30, berIdentity(0x30, berIdentity(6, descrOID), berIdentity(4, []byte("NetBotz Environment Sensor"))), berIdentity(0x30, berIdentity(6, objectOID), berIdentity(6, []byte{43, 6, 1, 4, 1, 0x83, 0x9b, 0x42, 0x83, 0x74, 1})))
	message := func(tag byte) []byte {
		return berIdentity(0x30, berIdentity(2, []byte{1}), berIdentity(4, []byte("test-community-secret")), berIdentity(tag, berIdentity(2, []byte{1}), berIdentity(2, []byte{0}), berIdentity(2, []byte{0}), bindings))
	}
	frame := identityFrame("10.0.0.9", "10.0.0.2", 161, 50000, message(0xa2), false, 0, 0, 0)
	query := identityFrame("10.0.0.2", "10.0.0.9", 50001, 161, message(0xa0), false, 0, 0, 0)
	dir := replayIdentityZeek(t, identityPCAP(frame, query), false)
	events := readIdentityEvents(t, dir, "snmp_device.log", "snmp")
	if len(events) != 1 || events[0].Subject["ip"] != "10.0.0.9" || events[0].Payload["system_object_id"] != "1.3.6.1.4.1.52674.500.1" {
		t.Fatalf("wrong response result: %+v", events)
	}
}

func TestZeekH3CResponsePreservesActualDescriptionLineBreaks(t *testing.T) {
	// The description text is from the 204 read-only observation export. This
	// reconstructs a response packet to test parsing; it is not a captured campus
	// packet, and does not retroactively prove ownership of the legacy aggregate.
	descr := "H3C Comware Platform Software, Software Version 7.1.070, Release 6126P20\r\nH3C E528C-PWR\r\nCopyright (c) 2004-2018 New H3C Technologies Co., Ltd. All rights reserved."
	bindings := berIdentity(0x30, berIdentity(0x30, berIdentity(6, []byte{43, 6, 1, 2, 1, 1, 1, 0}), berIdentity(4, []byte(descr))))
	pdu := berIdentity(0x30, berIdentity(2, []byte{1}), berIdentity(4, []byte("test-community-secret")), berIdentity(0xa2, berIdentity(2, []byte{1}), berIdentity(2, []byte{0}), berIdentity(2, []byte{0}), bindings))
	frame := identityFrame("10.0.0.9", "10.0.0.2", 161, 50000, pdu, false, 0, 0, 0)
	var frames [][]byte
	for _, vlan := range []byte{20, 21} {
		tagged := append([]byte(nil), frame[:12]...)
		tagged = append(tagged, 0x81, 0, 0, vlan)
		tagged = append(tagged, frame[12:]...)
		frames = append(frames, tagged)
	}
	dir := replayIdentityZeek(t, identityPCAP(frames...), false)
	events := readIdentityEvents(t, dir, "snmp_device.log", "snmp")
	if len(events) != 2 {
		t.Fatalf("expected both responses: %+v", events)
	}
	for i, e := range events {
		if e.Payload["system_description"] != descr || e.Payload["vlan"] != []string{"20", "21"}[i] {
			t.Fatalf("lost multiline/VLAN on response %d: %+v", i, e)
		}
	}
}

func TestZeekBACnetUpstreamPCAP(t *testing.T) {
	raw, err := os.ReadFile("testdata/icsnpp-bacnet-device-properties.pcap")
	if err != nil {
		t.Fatal(err)
	}
	dir := replayIdentityZeek(t, raw, true)
	events := readIdentityEvents(t, dir, "bacnet_property.log", "bacnet")
	found := false
	for _, e := range events {
		if e.Subject["ip"] != "192.168.0.24" || e.Payload["endpoint_identity_unverified"] != true {
			t.Fatalf("lost BACnet subdevice boundary: %+v", e)
		}
		if e.Payload["product_model"] == "SYSC MLX" {
			found = true
		}
	}
	if !found {
		t.Fatalf("upstream model response not decoded: %+v", events)
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "bacnet_device_control.log")); len(raw) > 0 {
		t.Fatal("device control log must be disabled")
	}
}

func TestZeekModbusIdentificationPCAP(t *testing.T) {
	mbap := func(body []byte) []byte {
		b := []byte{0, 1, 0, 0, 0, 0, 1}
		binary.BigEndian.PutUint16(b[4:], uint16(len(body)+1))
		return append(b, body...)
	}
	request := mbap([]byte{43, 14, 1, 0})
	response := mbap(append([]byte{43, 14, 1, 1, 0, 0, 2, 0, 7, 'T', 'e', 's', 't', 'C', 'o', 'r', 5, 7}, []byte("EnvUnit")...))
	client, server := "10.0.0.2", "10.0.0.9"
	frames := [][]byte{
		identityFrame(client, server, 50000, 502, nil, true, 100, 0, 2),
		identityFrame(server, client, 502, 50000, nil, true, 200, 101, 18),
		identityFrame(client, server, 50000, 502, nil, true, 101, 201, 16),
		identityFrame(client, server, 50000, 502, request, true, 101, 201, 24),
		identityFrame(server, client, 502, 50000, response, true, 201, uint32(101+len(request)), 24),
	}
	dir := replayIdentityZeek(t, identityPCAP(frames...), true)
	events := readIdentityEvents(t, dir, "modbus_read_device_identification.log", "modbus")
	if len(events) != 2 {
		t.Fatalf("expected two response fields: %+v", events)
	}
	found := false
	for _, e := range events {
		if e.Payload["product_model"] == "EnvUnit" {
			found = true
		}
		if e.Subject["ip"] != server || e.Payload["endpoint_identity_unverified"] != true {
			t.Fatalf("wrong Modbus source: %+v", e)
		}
	}
	if !found {
		t.Fatal("model response not decoded")
	}
}
