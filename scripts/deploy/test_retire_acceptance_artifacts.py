import hashlib
import importlib.util
import io
import json
import os
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
from contextlib import ExitStack

spec = importlib.util.spec_from_file_location('retire_acceptance', Path(__file__).with_name('retire-acceptance-artifacts.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RetirementSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base/'owned'
        self.root.mkdir()
        self.app = self.base/'application'
        (self.app/'releases').mkdir(parents=True)
        (self.app/'data').mkdir()
        for version in ('2026.10.01-release-r1', '2026.10.01-release-r2', '2026.10.01-release-r3'):
            (self.app/'releases'/version).mkdir()
        (self.app/'current').symlink_to(self.app/'releases/2026.10.01-release-r2')
        (self.app/'previous').symlink_to(self.app/'releases/2026.10.01-release-r1')
        header=bytearray(64)
        header[:7]=b'\x7fELF\x02\x01\x01'
        header[16:18]=(2).to_bytes(2,'little')
        header[18:20]=(62).to_bytes(2,'little')
        self.payload=bytes(header)+bytes(module.MIN_BYTES-64)

    def item(self, name='old.test', payload=None):
        path=self.root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(self.payload if payload is None else payload)
        info=path.stat();sha=hashlib.sha256(path.read_bytes()).hexdigest()
        return {'path':name,'bytes':info.st_size,'device':info.st_dev,'inode':info.st_ino,'mtime_ns':info.st_mtime_ns,'sha256':sha,'backup':{'path':str(self.base/'backup'/name),'bytes':info.st_size,'sha256':sha}}

    def plan(self, *items):
        return {'schema_version':1,'root':str(self.root),'application_root':str(self.app),'items':list(items)}

    def package(self, version):
        name='proxy-sentinel-'+version+'.tar.gz'
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz',compresslevel=1) as archive:
            manifest=json.dumps({'version':version,'os':'linux','arch':'amd64'}).encode()
            for entry,payload in [('release-manifest.json',manifest),('bin/example',os.urandom(module.MIN_BYTES))]:
                info=tarfile.TarInfo(entry);info.size=len(payload);archive.addfile(info,io.BytesIO(payload))
        return self.item(name,data.getvalue())

    def validate(self, plan, stack, active=None, referenced=False):
        return module.validate(self.root,self.app,plan,stack,active=set() if active is None else active,unit_reference=referenced)

    def apply(self, root_fd, candidates, stack, callback=None, active=None):
        return module.apply(self.root,self.app,root_fd,candidates,stack,active=set() if active is None else active,unit_reference=False,after_stage=callback)

    def test_backed_file_retired_and_audit_preserves_restore_mapping(self):
        item=self.item('linux-tests/old.test')
        with ExitStack() as stack:
            fd,rows=self.validate(self.plan(item),stack)
            result=self.apply(fd,rows,stack)
        self.assertFalse((self.root/item['path']).exists())
        self.assertEqual(result['retired_files'],1)
        entries=[json.loads(line) for line in Path(result['audit']).read_text().splitlines()]
        self.assertEqual(entries[0]['backup'],item['backup'])
        self.assertEqual(entries[-1]['phase'],'retired')
        self.assertEqual(list(self.root.glob('.retirement-staging-*')),[])

    def test_bad_backup_attestation_keeps_every_file(self):
        first,second=self.item('first.test'),self.item('second.test')
        second['backup']['sha256']='0'*64
        with ExitStack() as stack,self.assertRaises(ValueError):
            self.validate(self.plan(first,second),stack)
        self.assertTrue((self.root/'first.test').exists())
        self.assertTrue((self.root/'second.test').exists())

    def test_changed_contents_even_with_restored_mtime_rejected(self):
        item=self.item();path=self.root/item['path']
        with path.open('r+b') as target:target.seek(100);target.write(b'x')
        os.utime(path,ns=(item['mtime_ns'],item['mtime_ns']))
        with ExitStack() as stack,self.assertRaises(ValueError):self.validate(self.plan(item),stack)
        self.assertTrue(path.exists())

    def test_duplicate_or_traversal_paths_rejected(self):
        item=self.item()
        with ExitStack() as stack,self.assertRaises(ValueError):self.validate(self.plan(item,item),stack)
        for bad in ('../outside.test','/outside.test','nested/../old.test','nested//old.test'):
            with self.subTest(path=bad),ExitStack() as stack,self.assertRaises(ValueError):
                other=dict(item,path=bad);self.validate(self.plan(other),stack)
        self.assertTrue((self.root/'old.test').exists())

    def test_root_and_parent_symlinks_do_not_reach_outside(self):
        item=self.item('nested/old.test');outside=self.base/'outside'
        (self.root/'nested').rename(outside);(self.root/'nested').symlink_to(outside)
        with ExitStack() as stack,self.assertRaises(OSError):self.validate(self.plan(item),stack)
        self.assertTrue((outside/'old.test').exists())
        root=self.root;root.rename(self.base/'real-root');root.symlink_to(self.base/'real-root')
        with ExitStack() as stack,self.assertRaises(OSError):self.validate(self.plan(item),stack)

    def test_leaf_symlink_and_hardlink_are_rejected(self):
        item=self.item();path=self.root/item['path'];outside=self.base/'outside.test'
        path.rename(outside);path.symlink_to(outside)
        with ExitStack() as stack,self.assertRaises(OSError):self.validate(self.plan(item),stack)
        path.unlink();os.link(outside,path)
        item.update(inode=path.stat().st_ino,device=path.stat().st_dev,mtime_ns=path.stat().st_mtime_ns)
        with ExitStack() as stack,self.assertRaises(ValueError):self.validate(self.plan(item),stack)
        self.assertEqual(outside.read_bytes(),self.payload)

    def test_current_and_previous_packages_are_protected(self):
        for version in ('2026.10.01-release-r1','2026.10.01-release-r2'):
            item=self.package(version)
            with ExitStack() as stack,self.assertRaises(ValueError):self.validate(self.plan(item),stack)
            self.assertTrue((self.root/item['path']).exists())

    def test_package_became_current_after_validation_restored(self):
        item=self.package('2026.10.01-release-r3')
        with ExitStack() as stack:
            fd,rows=self.validate(self.plan(item),stack)
            (self.app/'current').unlink();(self.app/'current').symlink_to(self.app/'releases/2026.10.01-release-r3')
            with self.assertRaises(ValueError):self.apply(fd,rows,stack)
        self.assertTrue((self.root/item['path']).exists())

    def test_running_or_unit_referenced_artifact_not_retired(self):
        item=self.item()
        with ExitStack() as stack,self.assertRaises(ValueError):
            self.validate(self.plan(item),stack,active={(item['device'],item['inode'])})
        with ExitStack() as stack,self.assertRaises(ValueError):self.validate(self.plan(item),stack,referenced=True)
        self.assertTrue((self.root/item['path']).exists())

    def test_renamed_replacement_is_restored_without_deletion(self):
        item=self.item();path=self.root/item['path']
        with ExitStack() as stack:
            fd,rows=self.validate(self.plan(item),stack)
            replacement=self.root/'replacement';replacement.write_bytes(b'new content');replacement.replace(path)
            with self.assertRaises(ValueError):self.apply(fd,rows,stack)
        self.assertEqual(path.read_bytes(),b'new content')

    def test_concurrent_new_original_name_is_preserved(self):
        item=self.item();path=self.root/item['path']
        with ExitStack() as stack:
            fd,rows=self.validate(self.plan(item),stack)
            self.apply(fd,rows,stack,callback=lambda _:path.write_bytes(b'new original'))
        self.assertEqual(path.read_bytes(),b'new original')

    def test_checksum_change_in_staging_restores_all_survivors(self):
        a,b=self.item('a.test'),self.item('b.test')
        def mutate(staging):
            with (self.root/staging/'1').open('r+b') as target:target.seek(100);target.write(b'x')
        with ExitStack() as stack:
            fd,rows=self.validate(self.plan(a,b),stack)
            with self.assertRaises(ValueError):self.apply(fd,rows,stack,callback=mutate)
        self.assertEqual((self.root/'a.test').read_bytes(),self.payload)
        self.assertEqual((self.root/'b.test').read_bytes()[100:101],b'x')

    def test_restore_collision_keeps_both_versions(self):
        item=self.item();path=self.root/item['path']
        def collide(staging):
            path.write_bytes(b'new original')
            with (self.root/staging/'0').open('r+b') as target:target.seek(100);target.write(b'x')
        with ExitStack() as stack:
            fd,rows=self.validate(self.plan(item),stack)
            with self.assertRaises(ValueError):self.apply(fd,rows,stack,callback=collide)
        self.assertEqual(path.read_bytes(),b'new original')
        stages=list(self.root.glob('.retirement-staging-*'))
        self.assertEqual(len(stages),1)
        self.assertEqual((stages[0]/'0').read_bytes()[100:101],b'x')
        records=[json.loads(line) for p in (self.app/'data/acceptance-artifact-retirement-audit').glob('*.jsonl') for line in p.read_text().splitlines()]
        self.assertTrue(any(r['phase']=='restore_collision' for r in records))

    @unittest.skipUnless(Path('/proc').is_dir(), 'native Linux process inventory required')
    def test_real_running_linux_executable_is_protected(self):
        payload=Path('/usr/bin/sleep').read_bytes()
        self.assertTrue(payload.startswith(b'\x7fELF'))
        item=self.item('live.test',payload+bytes(max(0,module.MIN_BYTES-len(payload))))
        path=self.root/item['path'];path.chmod(0o755)
        child=subprocess.Popen([str(path),'30'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            self.assertIsNone(child.poll())
            with ExitStack() as stack,self.assertRaisesRegex(ValueError,'running'):
                module.validate(self.root,self.app,self.plan(item),stack,unit_reference=False)
            self.assertTrue(path.exists())
        finally:
            child.terminate();child.wait(timeout=5)

    def test_new_running_identity_after_staging_restores_files(self):
        item=self.item()
        with ExitStack() as stack:
            fd,rows=self.validate(self.plan(item),stack)
            with self.assertRaises(ValueError):
                self.apply(fd,rows,stack,active={(item['device'],item['inode'])})
        self.assertTrue((self.root/item['path']).exists())

    def test_core_dump_and_data_are_not_classified_as_executables(self):
        core=bytearray(self.payload);core[16:18]=(4).to_bytes(2,'little')
        for payload in (bytes(core),b'not an executable'+bytes(module.MIN_BYTES)):
            item=self.item(payload=payload)
            with ExitStack() as stack,self.assertRaises(ValueError):self.validate(self.plan(item),stack)
            self.assertTrue((self.root/item['path']).exists())


if __name__=='__main__':unittest.main()
