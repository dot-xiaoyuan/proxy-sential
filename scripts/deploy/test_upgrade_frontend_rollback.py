"""Isolated Linux upgrade control-flow replay; DB schema check is stubbed."""
import hashlib,json,os,shutil,subprocess,tarfile,tempfile,unittest
from pathlib import Path

class UpgradeRollbackReplay(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('SENTINEL_NATIVE_UPGRADE_REPLAY')=='30','30-only native replay')
    def test_frontend_pointer_and_application_rollback(self):
        with tempfile.TemporaryDirectory(prefix='sentinel-upgrade-replay-',dir='/opt') as temporary:
            root=Path(temporary);(root/'releases').mkdir();(root/'config').mkdir();tools=root/'tools';tools.mkdir();scripts=root/'scripts';scripts.mkdir()
            source=Path(__file__).resolve().parent
            for name in ['upgrade-application.sh','manage-frontend-previous.py','validate-release-archive.py']:
                shutil.copy2(source/name,scripts/name)
            (scripts/'verify-applied-migrations.py').write_text("print('isolated schema check stub')\n")
            (scripts/'verify-application-runtime.py').write_text("print('isolated runtime check stub')\n")
            def release(name,graph):
                p=root/'releases'/name;(p/'bin').mkdir(parents=True);(p/'frontend/dist/assets').mkdir(parents=True)
                (p/'bin/proxy-sentinel').write_text('#!/bin/sh\nexit 0\n');(p/'bin/proxy-sentinel').chmod(0o755)
                (p/'frontend/dist/index.html').write_text('<html>'+graph+'</html>');(p/'frontend/dist/assets'/('graph-'+graph+'.js')).write_text(graph)
                (p/'release-manifest.json').write_text(json.dumps({'version':name,'os':'linux','arch':'amd64'}))
                (p/'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(p))+'\n' for f in sorted(p.rglob('*')) if f.is_file()))
                return p
            a=release('a','A');b=release('b','B');(root/'current').symlink_to(b);(root/'previous').symlink_to(a)
            stubs={'systemctl':'exit 0', 'seq':'echo 1', 'sleep':'exit 0','curl':'if [ "$SENTINEL_FAIL_VERSION" = "$(basename "$(readlink -f "$PROXY_SENTINEL_ROOT/current")")" ]; then exit 1; fi; echo "{}"'}
            for name,body in stubs.items():
                p=tools/name;p.write_text('#!/bin/sh\n'+body+'\n');p.chmod(0o755)
            env=dict(os.environ,PROXY_SENTINEL_ROOT=str(root),PATH=str(tools)+os.pathsep+os.environ['PATH'],SENTINEL_FAIL_VERSION='')
            def upgrade(name,graph,fail=False):
                p=release(name,graph);archive=root/(name+'.tar.gz')
                with tarfile.open(archive,'w:gz') as output:output.add(p,arcname='.')
                shutil.rmtree(p);checksum=root/(name+'.tar.gz.sha256');checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
                env['SENTINEL_FAIL_VERSION']=name if fail else ''
                return subprocess.run(['bash',str(scripts/'upgrade-application.sh'),'--version',name,'--archive',str(archive),'--checksum',str(checksum)],env=env,text=True,capture_output=True,timeout=15)
            result=upgrade('c','B');self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual((root/'frontend-previous').resolve(),a);self.assertEqual((root/'current').resolve().name,'c')
            result=upgrade('d','C',True);self.assertNotEqual(result.returncode,0)
            self.assertIn('application upgrade failed; restored',result.stderr)
            self.assertEqual((root/'current').resolve().name,'c');self.assertEqual((root/'previous').resolve(),b);self.assertEqual((root/'frontend-previous').resolve(),a)
            result=upgrade('e','C');self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual((root/'frontend-previous').resolve().name,'c');self.assertEqual((root/'previous').resolve().name,'c')

if __name__=='__main__':unittest.main()
