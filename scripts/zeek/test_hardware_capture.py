import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class HardwareCaptureCompatibility(unittest.TestCase):
    def defaults(self, **options):
        text = (ROOT / "scripts/deploy/install-openeuler.sh").read_text()
        code = text[text.index('hardware_v2='):text.index('ingest_source_args=')]
        env = {k: v for k, v in os.environ.items() if not k.startswith("PROXY_SENTINEL_")}
        env.update(options)
        result = subprocess.run(
            ["bash", "-eu", "-c", 'root=/tmp/unused; zeek_log_dir=/tmp/logs; manage_zeek=true\n' + code +
             '\nprintf "%s\\n" "${PROXY_SENTINEL_ZEEK_SNMP_PATH-}" "${PROXY_SENTINEL_ZEEK_BACNET_PATH-}" "${PROXY_SENTINEL_ZEEK_MODBUS_PATH-}"'],
            env=env, text=True, capture_output=True, check=True,
        )
        return result.stdout.splitlines()

    def test_184_default_preserves_aggregate_stream(self):
        self.assertEqual(self.defaults(), ["/tmp/logs/snmp.log", "", ""])

    def test_shadow_and_v2_gate_direct_responses_independently(self):
        for gate in ("PROXY_SENTINEL_HARDWARE_V2", "PROXY_SENTINEL_HARDWARE_SHADOW"):
            with self.subTest(gate=gate):
                self.assertEqual(self.defaults(**{gate: "true"}), ["/tmp/logs/snmp_device.log", "", ""])
                self.assertEqual(self.defaults(**{gate: "true", "PROXY_SENTINEL_ZEEK_ICSNPP_ENABLED": "true"}),
                                 ["/tmp/logs/snmp_device.log", "/tmp/logs/bacnet_property.log", "/tmp/logs/modbus_read_device_identification.log"])

    def test_explicit_operator_paths_are_preserved(self):
        self.assertEqual(self.defaults(PROXY_SENTINEL_HARDWARE_V2="true", PROXY_SENTINEL_ZEEK_SNMP_PATH="/operator/snmp.log")[0], "/operator/snmp.log")

    def test_checksum_failure_precedes_plugin_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            config = binary / "zeek-config"
            config.write_text("#!/bin/sh\necho 8.2.0\n")
            config.chmod(0o755)
            lock = json.loads((ROOT / "assets/zeek/icsnpp.lock.json").read_text())
            prefix = root / "prefix"
            prefix.mkdir()
            (prefix / "payload").write_text("changed")
            (prefix / "manifest.json").write_text(json.dumps({"packages": lock["packages"], "zeek_version": "8.2.0", "files": {"payload": "0" * 64}}))
            result = subprocess.run(["bash", str(ROOT / "scripts/zeek/install-icsnpp.sh"), "--check", "--prefix", str(prefix)],
                                    env=dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"]), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("checksum mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
