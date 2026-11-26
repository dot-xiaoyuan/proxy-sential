package realtime

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNormalizeZeekSSHAndPostRotateCandidate 验证 zeek-ssh 源标准事件适配以及
// zeek-postrotate.sh 产出的 <base>.log-YYYYMMDD-HHMMSS 轮转文件名能被尾读器正确发现。
func TestNormalizeZeekSSHAndPostRotateCandidate(t *testing.T) {
	header := []byte("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tauth_success\tauth_attempts\tdirection\tclient\tserver")
	chunk := []byte("1764144000.123456\tC12345\t10.152.1.10\t54321\t10.131.253.1\t22\t2\tT\t1\tOUTBOUND\tSSH-2.0-OpenSSH_9.0\tSSH-2.0-Comware-7.1.070\n")

	events, stats, err := normalize(Source{Kind: "zeek-ssh", Path: "/opt/proxy-sentinel/data/zeek/logs/current/ssh.log"}, chunk, 128, "campus-204", header)
	if err != nil {
		t.Fatalf("normalize zeek-ssh failed: %v", err)
	}
	if stats.Emitted != 1 || len(events) != 1 {
		t.Fatalf("expected 1 emitted ssh event, got stats=%+v len=%d", stats, len(events))
	}
	if events[0].SourceEventType != "ssh" || events[0].Payload["ssh_server_banner"] != "SSH-2.0-Comware-7.1.070" {
		t.Fatalf("unexpected ssh normalized event: %+v", events[0])
	}

	dir := t.TempDir()
	active := filepath.Join(dir, "conn.log")
	rotated := filepath.Join(dir, "conn.log-20261126-190000")
	if err := os.WriteFile(active, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rotated, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	candidates := rotatedSourceCandidates(active)
	if len(candidates) != 1 || candidates[0] != rotated {
		t.Fatalf("expected rotated Zeek file %q in candidates, got %v", rotated, candidates)
	}
}
