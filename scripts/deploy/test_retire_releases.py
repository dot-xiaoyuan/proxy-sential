import importlib.util
import hashlib
import json
import mmap
import os
import stat
import tempfile
import tarfile
import unittest
from unittest.mock import patch
from pathlib import Path

spec=importlib.util.spec_from_file_location('retire_releases',Path(__file__).with_name('retire-releases.py'))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class RetirementGuards(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        (self.root/'releases').mkdir();(self.root/'data/release-backups').mkdir(parents=True)
        self.entry=self.release('2026.10.01-release-r8')
        for name in ['2026.10.01-release-r40','2026.10.01-release-r39']:self.release(name)
        (self.root/'current').symlink_to(self.root/'releases/2026.10.01-release-r40')
        (self.root/'previous').symlink_to(self.root/'releases/2026.10.01-release-r39')
        self.plan={'schema_version':1,'root':str(self.root),'releases':[self.entry]}
    def release(self,version):
        p=self.root/'releases'/version;p.mkdir()
        (p/'release-manifest.json').write_text(json.dumps({'version':version,'os':'linux','arch':'amd64'}))
        (p/'app').write_bytes(b'fixture')
        b=self.root/'data/release-backups'/('proxy-sentinel-'+version+'.tar.gz')
        with tarfile.open(b,'w:gz') as t:
            for f in p.iterdir():t.add(f,arcname=f.name)
        return {'version':version,'archive_sha256':hashlib.sha256(b.read_bytes()).hexdigest(),'files':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in p.iterdir()},'directories':['.']}
    def validate(self,**kwargs):return module.validate(self.root,self.plan,active_paths=kwargs.get('active_paths',[]),unit_contents=kwargs.get('unit_contents',[]))
    def test_preview_preserves_files_and_recovers_verified_payload(self):
        candidates=self.validate();self.assertEqual(len(candidates),1)
        self.assertTrue((self.root/'releases'/self.entry['version']/'app').is_file())
    def test_current_previous_running_and_unit_references_fail_closed(self):
        old=self.entry['version'];self.plan['releases']=[self.release('2026.10.01-release-r41')]
        version=self.plan['releases'][0]['version'];target=self.root/'releases'/version
        for pointer in ['current','previous']:
            link=self.root/pointer;original=link.resolve();link.unlink();link.symlink_to(target)
            with self.assertRaisesRegex(ValueError,'protected'):self.validate()
            link.unlink();link.symlink_to(original)
        self.plan['releases']=[self.entry]
        for kwargs in [{'active_paths':[str(self.root/'releases'/old/'app')]},{'unit_contents':[(str(self.root/'releases'/old/'app')).encode()]}]:
            with self.assertRaisesRegex(ValueError,'protected'):self.validate(**kwargs)
    def test_frontend_compatibility_release_is_protected(self):
        (self.root/'frontend-previous').symlink_to(self.root/'releases'/self.entry['version'])
        with self.assertRaisesRegex(ValueError,'protected'):self.validate()
    def test_tampered_backup_payload_extra_files_and_symlinks_rejected(self):
        p=self.root/'releases'/self.entry['version']
        (p/'app').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'payload'):self.validate()
        (p/'app').write_bytes(b'fixture');(p/'extra').write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError,'contents'):self.validate()
        (p/'extra').unlink();(p/'link').symlink_to(self.root/'outside')
        with self.assertRaisesRegex(ValueError,'symlink'):self.validate()
        (p/'link').unlink();backup=self.root/'data/release-backups'/('proxy-sentinel-'+self.entry['version']+'.tar.gz');backup.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'backup'):self.validate()
    def test_version_and_path_traversal_rejected(self):
        self.entry['version']='../outside'
        with self.assertRaises(ValueError):self.validate()
    def test_legacy_named_release_still_requires_exact_manifest_and_backup(self):
        entry=self.release('2026.09.16-device-current-r2')
        self.plan['releases']=[entry]
        candidates=self.validate()
        self.assertEqual(len(candidates),1)
        result=module.apply(self.root,candidates,active_paths=[],unit_contents=[])
        self.assertEqual(result['retired_releases'],1)
        self.assertTrue((self.root/'data/release-backups'/('proxy-sentinel-'+entry['version']+'.tar.gz')).is_file())
    def test_invalid_dated_name_and_legacy_manifest_identity_rejected(self):
        for name in ['2026.13.01-device-current','2026.09.16-device/other','2026.09.16-device..current']:
            self.entry['version']=name
            with self.assertRaises(ValueError):self.validate()
        entry=self.release('2026.09.16-device-profile')
        self.plan['releases']=[entry]
        (self.root/'releases'/entry['version']/'release-manifest.json').write_text('{}')
        with self.assertRaises(ValueError):self.validate()
    def test_application_configuration_reference_protects_release(self):
        (self.root/'config').mkdir()
        target=self.root/'releases'/self.entry['version']/'app'
        (self.root/'config'/'catalog.env').write_text('CATALOG='+str(target))
        with patch.object(module, 'active_executables', return_value=[]):
            with self.assertRaisesRegex(ValueError,'protected'):
                module.validate(self.root,self.plan)
    def test_exact_directory_references_protect_validation_and_apply(self):
        target=self.root/'releases'/self.entry['version']
        for references in [dict(active_paths=[str(target)],unit_contents=[]),
                           dict(active_paths=[],unit_contents=[('WorkingDirectory='+str(target)+'\n').encode()])]:
            with self.assertRaisesRegex(ValueError,'protected'):
                module.validate(self.root,self.plan,**references)
            candidates=self.validate()
            with self.assertRaisesRegex(ValueError,'protected'):
                module.apply(self.root,candidates,**references)
            self.assertTrue(target.exists())
    def test_similar_release_name_is_not_a_reference(self):
        target=str(self.root/'releases'/self.entry['version'])+'-other'
        self.assertEqual(len(self.validate(active_paths=[target],unit_contents=[target.encode()])),1)
    @unittest.skipUnless(os.path.isdir('/proc/self/fd'), 'Linux process references required')
    def test_process_working_directory_protects_release(self):
        target=self.root/'releases'/self.entry['version']
        original=Path.cwd()
        try:
            os.chdir(target)
            self.assertIn(str(target),module.active_executables())
            with self.assertRaisesRegex(ValueError,'protected'):
                module.validate(self.root,self.plan,unit_contents=[])
        finally:
            os.chdir(original)
    @unittest.skipUnless(os.path.isdir('/proc/self/fd'), 'Linux process references required')
    def test_open_and_mapped_release_files_protect_retirement(self):
        target=self.root/'releases'/self.entry['version']/'app'
        with target.open('rb') as source:
            mapped=mmap.mmap(source.fileno(),0,access=mmap.ACCESS_READ)
            try:
                paths=module.active_executables()
                self.assertIn(str(target),paths)
                with self.assertRaisesRegex(ValueError,'protected'):
                    module.validate(self.root,self.plan,unit_contents=[])
                source.close()
                self.assertIn(str(target),module.active_executables())
            finally:
                mapped.close()
    def test_unexpected_change_after_validation_prevents_retirement(self):
        candidates=self.validate();p=self.root/'releases'/self.entry['version'];(p/'extra').write_bytes(b'keep')
        with self.assertRaises(ValueError):module.apply(self.root,candidates,active_paths=[],unit_contents=[])
        self.assertTrue(p.exists())
    def test_file_mode_change_after_validation_prevents_retirement(self):
        candidates=self.validate();p=self.root/'releases'/self.entry['version']
        (p/'app').chmod(0o600)
        with self.assertRaisesRegex(ValueError,'contents changed'):
            module.apply(self.root,candidates,active_paths=[],unit_contents=[])
        self.assertTrue(p.exists())
    def test_snapshot_metadata_must_match_archive_and_source(self):
        p=self.root/'releases'/self.entry['version']
        self.entry['file_metadata']={x.name:{'mode':stat.S_IMODE(x.stat().st_mode),'uid':x.stat().st_uid,'gid':x.stat().st_gid} for x in p.iterdir()}
        self.assertEqual(len(self.validate()),1)
        self.entry['file_metadata']['app']['mode']=0o600
        with self.assertRaisesRegex(ValueError,'metadata mismatch'):self.validate()
    def test_backup_removed_after_validation_preserves_release(self):
        candidates=self.validate();candidates[0]['backup'].unlink()
        with self.assertRaisesRegex(ValueError,'backup'):module.apply(self.root,candidates,active_paths=[],unit_contents=[])
        self.assertTrue((self.root/'releases'/self.entry['version']).exists())
    def test_pointer_changed_after_validation_preserves_new_current(self):
        candidates=self.validate();p=self.root/'releases'/self.entry['version']
        (self.root/'current').unlink();(self.root/'current').symlink_to(p)
        with self.assertRaisesRegex(ValueError,'protected'):module.apply(self.root,candidates,active_paths=[],unit_contents=[])
        self.assertTrue(p.exists())
    def test_apply_preserves_restore_archive_and_writes_audit(self):
        candidates=self.validate();result=module.apply(self.root,candidates,active_paths=[],unit_contents=[])
        self.assertEqual(result['retired_releases'],1)
        self.assertFalse((self.root/'releases'/self.entry['version']).exists())
        self.assertTrue((self.root/'current'/'app').exists());self.assertTrue((self.root/'previous'/'app').exists())
        self.assertTrue((self.root/'data/release-backups'/('proxy-sentinel-'+self.entry['version']+'.tar.gz')).exists())
        self.assertTrue(Path(result['audit']).is_file())

if __name__=='__main__':unittest.main()
