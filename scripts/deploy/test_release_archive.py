import importlib.util
import io
import tempfile
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('release_archive', Path(__file__).with_name('validate-release-archive.py'))
module = importlib.util.module_from_spec(spec)
# Tests are committed before the guard module; an absent guard is a real failure.
spec.loader.exec_module(module)

class ReleaseArchiveTests(unittest.TestCase):
    def archive(self, entries):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        archive = Path(directory.name) / 'release.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            for name, size, kind in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = size
                output.addfile(member, io.BytesIO(b'x' * size) if kind == tarfile.REGTYPE else None)
        return archive, directory.name

    def validate(self, entries, available=3*1024**3, inodes=10000):
        archive, root = self.archive(entries)
        with patch.object(module.os, 'statvfs', return_value=SimpleNamespace(f_bavail=available, f_frsize=1, f_favail=inodes)):
            return module.validate(archive, root, 1024**3)

    def test_valid_regular_release_keeps_headroom(self):
        self.assertEqual(self.validate([('.', 0, tarfile.DIRTYPE), ('./bin', 0, tarfile.DIRTYPE), ('./bin/proxy-sentinel', 10, tarfile.REGTYPE)]), (10, 3))

    def test_insufficient_bytes_and_inodes_fail_before_extraction(self):
        with self.assertRaisesRegex(ValueError, 'headroom'):
            self.validate([('bin/proxy-sentinel', 10, tarfile.REGTYPE)], available=1024**3+9)
        with self.assertRaisesRegex(ValueError, 'inode'):
            self.validate([('bin/proxy-sentinel', 10, tarfile.REGTYPE)], inodes=1024)

    def test_traversal_link_and_duplicate_members_rejected(self):
        for entries in [[('../outside',0,tarfile.REGTYPE)], [('/absolute',0,tarfile.REGTYPE)], [('symlink',0,tarfile.SYMTYPE)], [('hardlink',0,tarfile.LNKTYPE)], [('file',0,tarfile.REGTYPE),('./file',0,tarfile.REGTYPE)]]:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.validate(entries)

    def test_invalid_reserve_cannot_disable_guard(self):
        archive, root = self.archive([('file',0,tarfile.REGTYPE)])
        for reserve in [-1,0,256*1024**2-1]:
            with self.assertRaises(ValueError):module.validate(archive,root,reserve)

if __name__=='__main__':unittest.main()
