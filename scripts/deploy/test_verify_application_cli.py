"""Release preflight must reject units missing candidate safety arguments."""

import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("verify-application-cli.py")
SPEC = importlib.util.spec_from_file_location("verify_application_cli", SCRIPT)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class VerifyApplicationCLITest(unittest.TestCase):
    def test_router_prober_requires_scope_and_interface_before_release(self):
        command = (
            "{ path=/opt/proxy-sentinel/current/bin/proxy-sentinel ; "
            "argv[]=/opt/proxy-sentinel/current/bin/proxy-sentinel router-prober run "
            "--postgres-dsn ${PROXY_SENTINEL_POSTGRES_DSN} --sensor-id sensor "
            "--output /tmp/router.jsonl ; ignore_errors=no }"
        )
        with mock.patch.object(VERIFY.runpy, "run_path", return_value={"UNIT_BINARIES": {
            "proxy-sentinel-router-prober.service": "proxy-sentinel"
        }}), mock.patch.object(VERIFY.subprocess, "check_output", return_value=command), \
                mock.patch.object(VERIFY.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "capture-scope-config, controlled-interface"):
                VERIFY.verify("/candidate", ["proxy-sentinel-router-prober.service"])
            run.assert_not_called()

    def test_router_prober_accepts_explicit_scope_and_interface(self):
        command = (
            "{ path=/opt/proxy-sentinel/current/bin/proxy-sentinel ; "
            "argv[]=/opt/proxy-sentinel/current/bin/proxy-sentinel router-prober run "
            "--postgres-dsn ${PROXY_SENTINEL_POSTGRES_DSN} --sensor-id sensor "
            "--output /tmp/router.jsonl --capture-scope-config /tmp/scope.json "
            "--controlled-interface bond0 ; ignore_errors=no }"
        )
        help_result = subprocess.CompletedProcess([], 0, stdout="\n".join(
            "  --" + flag + " value" for flag in (
                "postgres-dsn", "sensor-id", "output", "capture-scope-config", "controlled-interface"
            )
        ), stderr="")
        with mock.patch.object(VERIFY.runpy, "run_path", return_value={"UNIT_BINARIES": {
            "proxy-sentinel-router-prober.service": "proxy-sentinel"
        }}), mock.patch.object(VERIFY.subprocess, "check_output", return_value=command), \
                mock.patch.object(VERIFY.subprocess, "run", return_value=help_result):
            result = VERIFY.verify("/candidate", ["proxy-sentinel-router-prober.service"])
        self.assertEqual(result["verified_application_cli"][0]["checked_flags"], 5)


if __name__ == "__main__":
    unittest.main()
