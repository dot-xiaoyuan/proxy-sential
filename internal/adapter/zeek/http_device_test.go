package zeek

import (
	"strings"
	"testing"
)

func TestHTTPDeviceLogMapsServerAsSubject(t *testing.T) {
	header := "#separator \\x09\n#fields\tts\torig_h\tresp_h\thost\tserver\tstatus\tuser_agent\ttitle\tparser_version\n"
	body := "1794139571.914880\t10.152.11.8\t10.152.40.9\t10.152.40.9\tHikvision-Webs\t200\t-\tHikvision Network Camera\thttp-device/v1\n"
	var out strings.Builder
	stats, err := Convert(strings.NewReader(header+body), &out, Options{LogKind: "http-device"})
	if err != nil || stats.Emitted != 1 {
		t.Fatalf("convert: %v emitted=%d", err, stats.Emitted)
	}
	if !strings.Contains(out.String(), `"subject":{"ip":"10.152.40.9"`) {
		t.Fatalf("server not used as subject: %s", out.String())
	}
	if !strings.Contains(out.String(), `"server":"Hikvision-Webs"`) || !strings.Contains(out.String(), `"title":"Hikvision Network Camera"`) {
		t.Fatalf("server/title missing: %s", out.String())
	}
}
