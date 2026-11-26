import gzip
import os
import tempfile
import time
import unittest
from pathlib import Path

from zeek_log_prune import maintain


class ZeekLogPruneTest(unittest.TestCase):
    def test_compresses_old_rotated_keeps_recent_and_active_prunes_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            now = time.time()

            active = root / "conn.log"
            active.write_text("active line\n")

            recent_rot = root / "conn.log-20261126-190000"
            recent_rot.write_text("recent rotated\n")
            os.utime(recent_rot, (now - 600, now - 600))  # 10 分钟前，未到压缩窗口

            ready_rot = root / "dhcp.log-20261126-180000"
            ready_rot.write_text("dhcp line\n" * 200)
            os.utime(ready_rot, (now - 3600, now - 3600))  # 1 小时前，应压缩

            expired_high = root / "conn.log-20261125-100000.gz"
            with gzip.open(expired_high, "wb") as f:
                f.write(b"old conn\n")
            os.utime(expired_high, (now - 26 * 3600, now - 26 * 3600))  # >24h，应删

            kept_disc = root / "dhcp.log-20261125-100000.gz"
            with gzip.open(kept_disc, "wb") as f:
                f.write(b"kept dhcp\n")
            os.utime(kept_disc, (now - 36 * 3600, now - 36 * 3600))  # 36h < 72h，应保留

            expired_disc = root / "dhcp.log-20261123-090000.gz"
            with gzip.open(expired_disc, "wb") as f:
                f.write(b"expired dhcp\n")
            os.utime(expired_disc, (now - 80 * 3600, now - 80 * 3600))  # >72h，应删

            res = maintain(
                log_dir=root,
                now_ts=now,
                compress_delay_sec=35 * 60,
                high_vol_retention_sec=24 * 3600,
                discovery_retention_sec=72 * 3600,
                max_compress_per_run=32,
                dry_run=False,
            )
            self.assertEqual(res["errors"], [])
            self.assertEqual(res["compressed_files"], 1)
            self.assertEqual(res["deleted_files"], 2)
            self.assertEqual(res["skipped_recent"], 1)
            self.assertTrue(active.exists())
            self.assertTrue(recent_rot.exists())
            self.assertFalse(ready_rot.exists())
            self.assertTrue((root / "dhcp.log-20261126-180000.gz").exists())
            self.assertFalse(expired_high.exists())
            self.assertTrue(kept_disc.exists())
            self.assertFalse(expired_disc.exists())


if __name__ == "__main__":
    unittest.main()
