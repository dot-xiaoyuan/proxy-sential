package zeek

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestSSHBannerEventAttributesServerResponderOnly(t *testing.T) {
	line := `{"ts":1785232800.5,"uid":"ssh-1","id.orig_h":"10.10.1.5","id.orig_p":51234,"id.resp_h":"10.10.0.1","id.resp_p":22,"client":"SSH-2.0-OpenSSH_9.6","server":"SSH-2.0-Comware-7.1.070","vlan":"4005"}`
	var out bytes.Buffer
	stats, err := Convert(strings.NewReader(line+"\n"), &out, Options{LogKind: "ssh"})
	if err != nil || stats.Emitted != 1 {
		t.Fatalf("expected 1 emitted SSH event, got stats=%+v err=%v", stats, err)
	}
	var e normalized.Event
	if err := json.Unmarshal(out.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Subject["ip"] != "10.10.0.1" || e.Subject["mac"] != nil {
		t.Fatalf("SSH banner must attribute to server IP without L2 MAC: %+v", e.Subject)
	}
	if e.Payload["ssh_server_banner"] != "SSH-2.0-Comware-7.1.070" || e.Payload["attribution_side"] != "server" || e.Payload["is_response"] != true {
		t.Fatalf("unexpected SSH payload: %+v", e.Payload)
	}

	// 缺少服务端 Banner 的记录必须跳过
	noServer := `{"ts":1785232800.5,"uid":"ssh-2","id.orig_h":"10.10.1.5","id.orig_p":51234,"id.resp_h":"10.10.0.1","id.resp_p":22,"client":"SSH-2.0-OpenSSH_9.6"}`
	out.Reset()
	stats2, err := Convert(strings.NewReader(noServer+"\n"), &out, Options{LogKind: "ssh"})
	if err != nil || stats2.Emitted != 0 {
		t.Fatalf("SSH record without server banner must be skipped: stats=%+v err=%v", stats2, err)
	}
}
