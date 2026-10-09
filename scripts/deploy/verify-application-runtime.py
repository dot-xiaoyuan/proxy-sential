#!/usr/bin/env python3
"""Verify each upgraded systemd MainPID executes the selected release inode."""
import argparse,json,os
from pathlib import Path
import subprocess

UNIT_BINARIES={
 'proxy-sentinel-control-plane.service':'proxy-sentinel',
 'proxy-sentinel-ingest.service':'proxy-sentinel',
 'proxy-sentinel-risk-materializer.service':'proxy-sentinel',
 'proxy-sentinel-device-signal.service':'proxy-sentinel',
 'proxy-sentinel-read-model-realtime.service':'proxy-sentinel',
 'proxy-sentinel-read-model-coarse.service':'proxy-sentinel',
 'proxy-sentinel-recognition-materializer.service':'proxy-sentinel',
 'proxy-sentinel-identity-materializer.service':'proxy-sentinel',
 'proxy-sentinel-ncu-identity-materializer.service':'proxy-sentinel',
 'proxy-sentinel-application-materializer.service':'proxy-sentinel',
 'proxy-sentinel-discovery.service':'discovery-worker',
 'proxy-sentinel-ncu-identity-sync.service':'legacy-4k-identity-bridge',
}

def verify(root,release,units):
 root=Path(root).resolve(strict=True);release=Path(release).resolve(strict=True)
 if release.parent!=root/'releases' or (root/'current').resolve(strict=True)!=release:
  raise ValueError('selected release pointer mismatch')
 if not units or len(set(units))!=len(units):raise ValueError('nonempty unique units required')
 result=[]
 for unit in units:
  if unit not in UNIT_BINARIES:raise ValueError('unsupported application unit')
  expected=release/'bin'/UNIT_BINARIES[unit]
  if expected.is_symlink() or not expected.is_file():raise ValueError('candidate executable missing or symlink')
  pid=int(subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value'],text=True,timeout=5).strip())
  if pid<=0:raise ValueError('application process missing: '+unit)
  proc=Path('/proc')/str(pid)/'exe'
  if os.readlink(proc)!=str(expected):raise ValueError('application process runs another release: '+unit)
  actual=proc.stat();candidate=expected.stat()
  if (actual.st_dev,actual.st_ino)!=(candidate.st_dev,candidate.st_ino):raise ValueError('application executable inode mismatch: '+unit)
  # Fence a concurrent restart between reading MainPID and observing exe.
  again=int(subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value'],text=True,timeout=5).strip())
  if again!=pid:raise ValueError('application process changed during verification: '+unit)
  result.append({'unit':unit,'pid':pid,'executable':str(expected)})
 return {'release':release.name,'verified_application_processes':result}

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--root',required=True);parser.add_argument('--release',required=True);parser.add_argument('--units',nargs='+',required=True)
 args=parser.parse_args()
 try:print(json.dumps(verify(args.root,args.release,args.units)))
 except (OSError,ValueError,subprocess.SubprocessError) as error:raise SystemExit(str(error))
if __name__=='__main__':main()
