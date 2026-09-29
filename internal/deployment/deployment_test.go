package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestOpenEulerDeploymentScriptsAndPinnedImages(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	scripts := []string{
		"build-release.sh",
		"deploy-openeuler.sh",
		"install-openeuler.sh",
		"proxy-sentinelctl",
		"deploy-shadow-30.sh",
		"build-airgap-bundle.sh",
		"install-airgap-openeuler.sh",
		"deploy-airgap-openeuler.sh",
		"reset-openeuler.sh",
		filepath.Join("..", "testbed", "setup-194.sh"),
		filepath.Join("..", "testbed", "run-194.sh"),
		filepath.Join("..", "testbed", "run-suite-194.sh"),
		filepath.Join("..", "testbed", "cleanup-194.sh"),
		filepath.Join("..", "testbed", "verify-30.sh"),
		filepath.Join("..", "testbed", "fault-30.sh"),
		filepath.Join("..", "testbed", "performance-30.sh"),
	}
	for _, name := range scripts {
		path := filepath.Join(root, "scripts", "deploy", name)
		if output, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("%s is not valid bash: %s", name, output)
		}
	}
	environment, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "storage.env.example"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(environment)
	if strings.Contains(text, ":latest") {
		t.Fatal("deployment example must not contain floating latest images")
	}
	pinned := regexp.MustCompile(`(?m)^(POSTGRES_IMAGE|CLICKHOUSE_IMAGE)=srun-docker\.pkg\.coding\.net/.+@sha256:[a-f0-9]{64}$`)
	if len(pinned.FindAllString(text, -1)) != 2 {
		t.Fatal("both storage images must be pinned to Coding registry digests")
	}
	installer, err := os.ReadFile(filepath.Join(root, "scripts", "deploy", "install-openeuler.sh"))
	if err != nil {
		t.Fatal(err)
	}
	installerText := string(installer)
	for _, required := range []string{"openEuler", "x86_64", "proxy-sentinelctl\" backup", " migrate ", "--backfill-application-read-model", "PROXY_SENTINEL_MIGRATION_TIMEOUT", "PROXY_SENTINEL_INSTALL_HEALTH_URL", "completed_backfills", "rollback_install", "systemctl stop proxy-sentinel-control-plane.service", "systemctl start proxy-sentinel-risk-materializer.service", "old_target\" == \"$root/current", "device-fingerprint-auto-update=false", "curl -fsS", "docker login", "proxy-sentinel-ingest.service", "ingest run", "--zeek-conn", "--zeek-http", "--zeek-ssl", "--zeek-x509", "start_storage_direct", "OnActiveSec=2min"} {
		if !strings.Contains(installerText, required) {
			t.Fatalf("installer is missing production guard %q", required)
		}
	}
	if strings.Contains(installerText, "git pull") {
		t.Fatal("target installer must not pull source code")
	}
	shadowStart := strings.Index(installerText, "ExecStart=$root/current/bin/proxy-sentinel shadow run")
	if shadowStart >= 0 {
		shadowEnd := strings.Index(installerText[shadowStart:], "\nEOF")
		if shadowEnd >= 0 && strings.Contains(installerText[shadowStart:shadowStart+shadowEnd], "--store-timeout") {
			t.Fatal("shadow systemd unit must not pass newly introduced optional flags that break application rollback")
		}
	}
	if strings.Contains(installerText, "Docker Compose v2 is unavailable\"") {
		t.Fatal("installer must support the openEuler Docker package without requiring Compose v2")
	}
	airgapInstaller, err := os.ReadFile(filepath.Join(root, "scripts", "deploy", "install-airgap-openeuler.sh"))
	if err != nil {
		t.Fatal(err)
	}
	airgapText := string(airgapInstaller)
	for _, required := range []string{"[失败] 阶段", "sha256sum -c SHA256SUMS", "--disablerepo='*'", "POSTGRES_IMAGE_ID", "CLICKHOUSE_IMAGE_ID", "airgap-${postgres_source_digest#sha256:}", "proxy-sentinelctl doctor", "Srun@4000", "请登录后立即"} {
		if !strings.Contains(airgapText, required) {
			t.Fatalf("airgap installer is missing offline-install guard %q", required)
		}
	}
	if strings.Contains(airgapText, "/root/proxy-sentinel-admin-password") {
		t.Fatal("airgap installer must not persist the documented initial administrator password")
	}
	resetter, err := os.ReadFile(filepath.Join(root, "scripts", "deploy", "reset-openeuler.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--confirm-host", "--preserve-docker-data", "postgres|clickhouse):airgap-", "验证干净状态"} {
		if !strings.Contains(string(resetter), required) {
			t.Fatalf("reset script is missing destructive-operation guard %q", required)
		}
	}
}
