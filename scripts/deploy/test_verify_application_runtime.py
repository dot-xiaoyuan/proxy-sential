"""Runtime verification for an intentionally pinned NCU materializer."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("verify-application-runtime.py")
SPEC = importlib.util.spec_from_file_location("verify_application_runtime", MODULE_PATH)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)

PINNED = "proxy-sentinel-ncu-identity-materializer.service"
NORMAL = "proxy-sentinel-control-plane-eventbus.service"


class RuntimeVerifierTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.release = self.binary("r61")
        self.old = self.binary("r25")
        (self.root / "current").symlink_to(self.release.parent.parent)
        self.proc = self.root / "proc"
        self.process(411, self.old)
        self.process(412, self.release)
        self.pids = {PINNED: 411, NORMAL: 412}
        self.configured = self.old
        self.argv_executable = None
        self.exec_start_calls = 0

    def binary(self, name):
        path = self.root / "releases" / name / "bin" / "proxy-sentinel"
        path.parent.mkdir(parents=True)
        path.write_bytes(name.encode())
        return path

    def process(self, pid, executable):
        path = self.proc / str(pid) / "exe"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        path.symlink_to(executable)

    def systemctl(self, args, **kwargs):
        self.assertEqual(args[:2], ["systemctl", "show"])
        unit, prop = args[2], args[4]
        if prop == "MainPID":
            return str(self.pids[unit]) + "\n"
        self.assertEqual(prop, "ExecStart")
        self.exec_start_calls += 1
        target = self.configured
        argv = self.argv_executable or target
        return f"{{ path={target} ; argv[]={argv} read-model run --lane identity ; ignore_errors=no; }}\n"

    def verify(self, units):
        with patch.object(runtime.subprocess, "check_output", side_effect=self.systemctl):
            return runtime.verify(self.root, self.release.parent.parent, units, self.proc)

    def test_pinned_materializer_and_candidate_services_are_verified(self):
        result = self.verify([PINNED, NORMAL])
        self.assertEqual([item["executable"] for item in result["verified_application_processes"]],
                         [str(self.old), str(self.release)])
        self.assertEqual(self.exec_start_calls, 2)

    def test_other_service_cannot_run_an_old_release(self):
        self.process(412, self.old)
        with self.assertRaisesRegex(ValueError, "runs another release"):
            self.verify([NORMAL])

    def test_dhcp_archive_reader_keeps_its_explicit_immutable_release(self):
        for unit in ("proxy-sentinel-ingest-stream-dhcp-message-r1.service",
                     "proxy-sentinel-recognition-materializer.service"):
            with self.subTest(unit=unit):
                self.process(411, self.old)
                self.pids[unit] = 411
                result = self.verify([unit, NORMAL])
                self.assertEqual(result["verified_application_processes"][0]["executable"], str(self.old))
                self.process(411, self.release)
                with self.assertRaisesRegex(ValueError, "runs another release"):
                    self.verify([unit])

    def test_pinned_process_must_match_configured_executable(self):
        self.process(411, self.release)
        with self.assertRaisesRegex(ValueError, "runs another release"):
            self.verify([PINNED])

    def test_pinned_executable_must_be_an_immutable_release_file(self):
        outside = self.root / "other" / "proxy-sentinel"
        outside.parent.mkdir()
        outside.write_bytes(b"outside")
        self.configured = outside
        with self.assertRaisesRegex(ValueError, "outside immutable releases"):
            self.verify([PINNED])

    def test_pinned_release_binary_symlink_is_rejected(self):
        self.old.unlink()
        self.old.symlink_to(self.release)
        with self.assertRaisesRegex(ValueError, "not an immutable release file"):
            self.verify([PINNED])

    def test_pinned_exec_start_path_and_argv_must_agree(self):
        self.argv_executable = self.release
        with self.assertRaisesRegex(ValueError, "cannot verify pinned unit ExecStart"):
            self.verify([PINNED])

    def test_pinned_unit_can_explicitly_follow_current(self):
        self.configured = self.root / "current" / "bin" / "proxy-sentinel"
        self.process(411, self.release)
        result = self.verify([PINNED])
        self.assertEqual(result["verified_application_processes"][0]["executable"], str(self.release))

    def test_exec_start_change_during_verification_is_rejected(self):
        def changed(args, **kwargs):
            if args[4] == "ExecStart" and self.exec_start_calls == 1:
                self.configured = self.release
            return self.systemctl(args, **kwargs)
        with patch.object(runtime.subprocess, "check_output", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "ExecStart changed"):
                runtime.verify(self.root, self.release.parent.parent, [PINNED], self.proc)


if __name__ == "__main__":
    unittest.main()
