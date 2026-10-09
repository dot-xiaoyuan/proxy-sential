"""30-only release runtime replay; real owned processes, stubbed systemd/schema."""
import hashlib,json,os,shutil,signal,subprocess,tarfile,tempfile,unittest
from pathlib import Path

@unittest.skipUnless(os.environ.get('SENTINEL_NATIVE_UPGRADE_REPLAY')=='30','30-only native replay')
class RuntimeUpgradeReplay(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sentinel-runtime-replay-',dir='/opt');self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);(self.root/'releases').mkdir();(self.root/'config').mkdir();(self.root/'tools').mkdir();(self.root/'scripts').mkdir()
  source=Path(__file__).resolve().parent
  for name in ['upgrade-application.sh','manage-frontend-previous.py','validate-release-archive.py','verify-application-runtime.py']:
   if (source/name).exists():shutil.copy2(source/name,self.root/'scripts'/name)
  (self.root/'scripts/verify-applied-migrations.py').write_text("print('isolated schema check stub')\n")
  self.release('a');self.release('b');(self.root/'current').symlink_to(self.root/'releases/b');(self.root/'previous').symlink_to(self.root/'releases/a')
  controller='''#!/usr/bin/env python3
import json,os,signal,subprocess,sys
from pathlib import Path
root=Path(os.environ['PROXY_SENTINEL_ROOT']);args=sys.argv[1:];pidfile=root/'pid'
if args[0]=='is-active':sys.exit(0 if args[-1]=='proxy-sentinel-control-plane.service' else 1)
if args[0]=='show':
 print(pidfile.read_text().strip());sys.exit(0)
if args[0]=='restart':
 version=(root/'current').resolve().name
 if version==os.environ.get('SENTINEL_KEEP_OLD',''):sys.exit(0)
 if pidfile.exists():
  pid=int(pidfile.read_text());exe=Path('/proc/'+str(pid)+'/exe')
  try:
   if str(exe.resolve()).startswith(str(root/'releases')+'/'):os.kill(pid,signal.SIGTERM)
  except FileNotFoundError:pass
 child=subprocess.Popen([str(root/'current/bin/proxy-sentinel'),'300'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 pidfile.write_text(str(child.pid));sys.exit(0)
sys.exit(1)
'''
  stubs={'systemctl':controller,'seq':'#!/bin/sh\necho 1\n','sleep':'#!/bin/sh\nexit 0\n','curl':'#!/bin/sh\necho "{}"\n'}
  for name,text in stubs.items():p=self.root/'tools'/name;p.write_text(text);p.chmod(0o755)
  self.env=dict(os.environ,PROXY_SENTINEL_ROOT=str(self.root),PATH=str(self.root/'tools')+os.pathsep+os.environ['PATH'])
  subprocess.run(['systemctl','restart','proxy-sentinel-control-plane.service'],env=self.env,check=True)
  self.addCleanup(self.stop)
 def stop(self):
  p=self.root/'pid'
  if p.exists():
   pid=int(p.read_text())
   try:
    if os.readlink('/proc/'+str(pid)+'/exe').startswith(str(self.root/'releases')+'/'):os.kill(pid,signal.SIGTERM)
   except FileNotFoundError:pass
 def release(self,name):
  p=self.root/'releases'/name;(p/'bin').mkdir(parents=True);(p/'frontend/dist').mkdir(parents=True)
  shutil.copy2('/usr/bin/sleep',p/'bin/proxy-sentinel')
  (p/'frontend/dist/index.html').write_text('same frontend')
  (p/'release-manifest.json').write_text(json.dumps({'version':name,'os':'linux','arch':'amd64'}))
  (p/'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(p))+'\n' for f in sorted(p.rglob('*')) if f.is_file()))
  return p
 def upgrade(self,name):
  p=self.release(name);archive=self.root/(name+'.tar.gz')
  with tarfile.open(archive,'w:gz') as output:output.add(p,arcname='.')
  shutil.rmtree(p);checksum=self.root/(name+'.tar.gz.sha256');checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
  return subprocess.run(['bash',str(self.root/'scripts/upgrade-application.sh'),'--version',name,'--archive',str(archive),'--checksum',str(checksum)],env=self.env,text=True,capture_output=True,timeout=20)
 def test_healthy_old_executable_cannot_accept_candidate(self):
  self.env['SENTINEL_KEEP_OLD']='c'
  result=self.upgrade('c')
  self.assertNotEqual(result.returncode,0,'healthy stale executable accepted candidate: '+result.stdout+result.stderr)
  self.assertEqual((self.root/'current').resolve().name,'b')
  self.assertEqual((self.root/'previous').resolve().name,'a')
  pid=int((self.root/'pid').read_text())
  self.assertEqual(os.readlink('/proc/'+str(pid)+'/exe'),str(self.root/'releases/b/bin/proxy-sentinel'))
 def test_actual_candidate_executable_accepts_and_preserves_rollback(self):
  result=self.upgrade('c');self.assertEqual(result.returncode,0,result.stdout+result.stderr)
  self.assertEqual((self.root/'current').resolve().name,'c');self.assertEqual((self.root/'previous').resolve().name,'b')
  pid=int((self.root/'pid').read_text())
  self.assertEqual(os.readlink('/proc/'+str(pid)+'/exe'),str(self.root/'releases/c/bin/proxy-sentinel'))

if __name__=='__main__':unittest.main()
