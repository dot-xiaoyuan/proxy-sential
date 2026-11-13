import gzip
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("protect_device_signal_rotations.py")
spec = importlib.util.spec_from_file_location("rotation_protector", SCRIPT)
protector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protector)


class RotationProtectionTest(unittest.TestCase):
    def test_archives_compressed_generations_without_changing_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "ttl.jsonl"
            recovery = directory / "protected"
            recovery.mkdir()
            source.write_bytes(b"first\n")
            live = recovery / "ttl-live-initial.jsonl"
            os.link(source, live)
            self.assertIn("waiting", protector.protect(source, recovery))

            os.rename(source, Path(f"{source}.1"))
            source.write_bytes(b"second\n")
            self.assertIn("waiting", protector.protect(source, recovery))

            self.compress_rotation(source)
            source.write_bytes(b"third\n")
            protector.protect(source, recovery)
            first = protector.chain_path(recovery, 0)
            self.assertTrue(protector.same_file(first, Path(f"{source}.2.gz")))

            os.rename(Path(f"{source}.2.gz"), Path(f"{source}.3.gz"))
            self.compress_rotation(source)
            source.write_bytes(b"fourth\n")
            protector.protect(source, recovery)
            second = protector.chain_path(recovery, 1)
            self.assertTrue(protector.same_file(second, Path(f"{source}.2.gz")))
            self.assertEqual(gzip.open(first, "rb").read(), b"first\n")
            self.assertEqual(gzip.open(second, "rb").read(), b"second\n")

            os.unlink(Path(f"{source}.3.gz"))
            os.unlink(Path(f"{source}.2.gz"))
            with self.assertRaisesRegex(RuntimeError, "continuity cannot be proved"):
                protector.protect(source, recovery)
            self.assertEqual(source.read_bytes(), b"fourth\n")

    @staticmethod
    def compress_rotation(source):
        previous = Path(f"{source}.1")
        with gzip.open(Path(f"{source}.2.gz"), "wb") as output:
            output.write(previous.read_bytes())
        os.unlink(previous)
        os.rename(source, previous)


if __name__ == "__main__":
    unittest.main()
