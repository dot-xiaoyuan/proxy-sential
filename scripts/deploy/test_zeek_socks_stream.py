import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('collector',Path(__file__).with_name('activate-zeek-socks-stream.py'))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
ROOT = Path(__file__).resolve().parents[2]


class CollectorArchiveTests(unittest.TestCase):
    def test_version_output_uses_name_or_absolute_path(self):
        for output in ('zeek version 8.0.9','/usr/local/zeek/bin/zeek version 8.0.9\n'):
            self.assertEqual(collector.parse_version(output),'8.0.9')

    def test_invalid_version_output(self):
        for output in ('another version 8.0.9','zeek version bogus','zeek 8.0.9','zeek version 8.0.9\nextra'):
            with self.assertRaises(ValueError): collector.parse_version(output)

    def test_release_payload_matches_source(self):
        manifest = json.loads((ROOT/'assets/zeek/plugins/Sentinel_SOCKSStream.json').read_text())
        content = collector.validate_payload(ROOT/'assets/zeek/plugins/Sentinel_SOCKSStream.tgz',manifest)
        for name in ('__load__.zeek','main.zeek','dpd.sig'):
            self.assertEqual(content[collector.PREFIX+'scripts/'+name],(ROOT/'collectors/zeek/socks-stream/scripts'/name).read_bytes())
        for name,digest in manifest['source_files'].items():
            self.assertEqual(collector.sha((ROOT/name).read_bytes()),digest)

    def invalid(self, extra=None, omitted=None, tamper=None, duplicate=False):
        manifest = json.loads((ROOT/'assets/zeek/plugins/Sentinel_SOCKSStream.json').read_text())
        content = collector.validate_payload(ROOT/'assets/zeek/plugins/Sentinel_SOCKSStream.tgz',manifest)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'collector.tgz'
            with tarfile.open(path,'w:gz') as output:
                for name,value in content.items():
                    if name == omitted: continue
                    if name == tamper: value += b'changed'
                    info = tarfile.TarInfo(name);info.size=len(value)
                    output.addfile(info,io.BytesIO(value))
                    if duplicate:
                        output.addfile(info,io.BytesIO(value));duplicate=False
                if extra:
                    info = tarfile.TarInfo(extra)
                    if extra.endswith('symlink'):
                        info.type = tarfile.SYMTYPE;info.linkname='/etc/passwd'
                    output.addfile(info)
            manifest['archive_sha256']=collector.sha(path.read_bytes())
            with self.assertRaises(ValueError):
                collector.validate_payload(path,manifest)

    def test_unexpected_member(self): self.invalid(extra=collector.PREFIX+'unreviewed')
    def test_path_traversal(self): self.invalid(extra='../outside')
    def test_absolute_path(self): self.invalid(extra='/tmp/outside')
    def test_symlink(self): self.invalid(extra=collector.PREFIX+'symlink')
    def test_missing_file(self): self.invalid(omitted=collector.PREFIX+'scripts/main.zeek')
    def test_changed_file(self): self.invalid(tamper=collector.PREFIX+'scripts/main.zeek')
    def test_duplicate_file(self): self.invalid(duplicate=True)
    def test_archive_checksum(self):
        manifest = json.loads((ROOT/'assets/zeek/plugins/Sentinel_SOCKSStream.json').read_text())
        manifest['archive_sha256']='0'*64
        with self.assertRaises(ValueError):collector.validate_payload(ROOT/'assets/zeek/plugins/Sentinel_SOCKSStream.tgz',manifest)


class CollectorConfigurationTests(unittest.TestCase):
    def test_create_replace_remove(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'socks-stream.conf'
            collector.replace_dropin(path,None,b'old')
            collector.replace_dropin(path,b'old',b'new')
            self.assertEqual(path.read_bytes(),b'new')
            collector.replace_dropin(path,b'new',None)
            self.assertFalse(path.exists())

    def test_changed_configuration_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'socks-stream.conf';path.write_bytes(b'external')
            with self.assertRaises(ValueError):collector.replace_dropin(path,b'old',b'new')
            self.assertEqual(path.read_bytes(),b'external')

    def test_failed_stage_write_preserves_previous_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'socks-stream.conf';path.write_bytes(b'old')
            with mock.patch.object(collector.os,'fsync',side_effect=OSError('private staged write failed')):
                with self.assertRaises(OSError):collector.replace_dropin(path,b'old',b'new')
            self.assertEqual(path.read_bytes(),b'old')
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()),['socks-stream.conf'])

    def test_symlink_is_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'external';target.write_bytes(b'old')
            path=Path(directory)/'socks-stream.conf';path.symlink_to(target)
            with self.assertRaises(ValueError):collector.replace_dropin(path,b'old',b'new')
            self.assertEqual(target.read_bytes(),b'old')

    def test_refresh_failure_restores_previous_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'socks-stream.conf';path.write_bytes(b'old')
            seen=[]
            def refresh():
                seen.append(path.read_bytes())
                if len(seen)==1:raise RuntimeError('candidate readiness failed')
            with self.assertRaisesRegex(RuntimeError,'candidate readiness failed'):
                collector.switch_collector(path,b'old',b'new',refresh)
            self.assertEqual(seen,[b'new',b'old'])
            self.assertEqual(path.read_bytes(),b'old')

    def test_first_install_failure_removes_own_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'socks-stream.conf';seen=[]
            def refresh():
                seen.append(path.read_bytes() if path.exists() else None)
                if len(seen)==1:raise RuntimeError('candidate readiness failed')
            with self.assertRaises(RuntimeError):collector.switch_collector(path,None,b'new',refresh)
            self.assertEqual(seen,[b'new',None])

    def test_failed_recovery_does_not_republish_candidate_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'socks-stream.conf';path.write_bytes(b'old');seen=[]
            def refresh():
                seen.append(path.read_bytes())
                raise RuntimeError('service unavailable')
            with self.assertRaises(RuntimeError):collector.switch_collector(path,b'old',b'new',refresh)
            self.assertEqual(seen,[b'new',b'old'])
            self.assertEqual(path.read_bytes(),b'old')

    def test_external_change_prevents_rollback_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'socks-stream.conf';path.write_bytes(b'old')
            def refresh():
                path.write_bytes(b'external')
                raise RuntimeError('failed')
            with self.assertRaisesRegex(ValueError,'changed externally'):
                collector.switch_collector(path,b'old',b'new',refresh)
            self.assertEqual(path.read_bytes(),b'external')

    def test_foreign_plugin_path_is_not_managed(self):
        parent=Path('/opt/proxy-sentinel/collectors/zeek-plugins')
        for text in ('[Service]\nEnvironment="ZEEK_PLUGIN_PATH=/tmp/other"\n','[Service]\nEnvironment="ZEEK_PLUGIN_PATH='+str(parent)+'/Sentinel_SOCKSStream-0123456789abcdef:other"\n'):
            with self.assertRaises(ValueError):collector.managed_target(text,parent)


if __name__ == '__main__': unittest.main()
