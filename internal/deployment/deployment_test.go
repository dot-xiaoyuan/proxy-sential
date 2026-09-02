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
	scripts := []string{"build-release.sh", "deploy-openeuler.sh", "install-openeuler.sh", "proxy-sentinelctl", "deploy-shadow-30.sh"}
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
	for _, required := range []string{"openEuler", "x86_64", "proxy-sentinelctl\" backup", " migrate ", "rollback_install", "device-fingerprint-auto-update=false", "curl -fsS", "docker login"} {
		if !strings.Contains(installerText, required) {
			t.Fatalf("installer is missing production guard %q", required)
		}
	}
	if strings.Contains(installerText, "git pull") {
		t.Fatal("target installer must not pull source code")
	}
	if strings.Contains(installerText, "ExecStart=$root/current/bin/proxy-sentinel shadow run") && strings.Contains(installerText, "--store-timeout") {
		t.Fatal("systemd units must not pass newly introduced optional flags that break application rollback")
	}
}
