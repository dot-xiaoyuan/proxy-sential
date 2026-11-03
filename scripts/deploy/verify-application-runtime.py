#!/usr/bin/env python3
"""Verify upgraded MainPIDs and explicitly pinned systemd executables."""
import argparse,json,os,re
from pathlib import Path
import subprocess

UNIT_BINARIES={
 'proxy-sentinel-control-plane.service':'proxy-sentinel',
 'proxy-sentinel-control-plane-eventbus.service':'proxy-sentinel',
 'proxy-sentinel-ingest.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-dhcp-binding-b56.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-dhcp-message-r1.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-packet-b54.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-handshake-b54.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-packet-b76.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-handshake-b76.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-dhcp-layered-r8.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-packet-layered-r7.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-handshake-layered-r7.service':'proxy-sentinel',
 'proxy-sentinel-ingest-stream-flow-syn.service':'proxy-sentinel',
 'proxy-sentinel-risk-materializer.service':'proxy-sentinel',
 'proxy-sentinel-device-signal.service':'proxy-sentinel',
 'proxy-sentinel-handshake-signal.service':'proxy-sentinel',
 'proxy-sentinel-flow-syn-signal.service':'proxy-sentinel',
 'proxy-sentinel-router-prober.service':'proxy-sentinel',
 'proxy-sentinel-read-model-realtime.service':'proxy-sentinel',
 'proxy-sentinel-read-model-coarse.service':'proxy-sentinel',
 'proxy-sentinel-recognition-materializer.service':'proxy-sentinel',
 'proxy-sentinel-inventory.service':'proxy-sentinel',
 'proxy-sentinel-inventory-backfill.service':'proxy-sentinel',
 'proxy-sentinel-identity-materializer.service':'proxy-sentinel',
 'proxy-sentinel-ncu-identity-materializer.service':'proxy-sentinel',
 'proxy-sentinel-application-materializer.service':'proxy-sentinel',
 'proxy-sentinel-discovery.service':'discovery-worker',
 'proxy-sentinel-passive-discovery.service':'passive-discovery-worker',
 'proxy-sentinel-ncu-identity-sync.service':'legacy-4k-identity-bridge',
 'proxy-sentinel-recognition-minute-shadow.service':'recognition-minute-shadow',
}

# These readers are upgraded independently: NCU derivation and the DHCP
# archive-resume reader both have deliberately pinned immutable executables.
# Verify their exact configured path and inode, never just accept any old PID.
PINNED_UNITS={'proxy-sentinel-ncu-identity-materializer.service',
              'proxy-sentinel-recognition-materializer.service',
              'proxy-sentinel-ingest-stream-dhcp-message-r1.service'}

def pinned_executable(root,unit,binary):
 value=subprocess.check_output(['systemctl','show',unit,'-p','ExecStart','--value'],text=True,timeout=5).strip()
 match=re.match(r'^\{\s*path=([^\s;]+)\s*;\s*argv\[\]=([^\s;]+)(?:\s|;)',value)
 if not match or match.group(1)!=match.group(2):
  raise ValueError('cannot verify pinned unit ExecStart: '+unit)
 configured=Path(match.group(1))
 if configured==root/'current'/'bin'/binary:
  return (root/'current'/'bin'/binary).resolve(strict=True)
 if (configured.parent.parent.parent!=root/'releases' or configured.parent.name!='bin' or
     configured.name!=binary or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}',configured.parent.parent.name)):
  raise ValueError('pinned unit executable is outside immutable releases: '+unit)
 if configured.is_symlink() or not configured.is_file() or configured.resolve(strict=True)!=configured:
  raise ValueError('pinned unit executable is not an immutable release file: '+unit)
 return configured

def verify(root,release,units,proc_root=Path('/proc')):
 root=Path(root).resolve(strict=True);release=Path(release).resolve(strict=True)
 if release.parent!=root/'releases' or (root/'current').resolve(strict=True)!=release:
  raise ValueError('selected release pointer mismatch')
 if not units or len(set(units))!=len(units):raise ValueError('nonempty unique units required')
 result=[]
 for unit in units:
  if unit not in UNIT_BINARIES:raise ValueError('unsupported application unit')
  candidate=release/'bin'/UNIT_BINARIES[unit]
  if candidate.is_symlink() or not candidate.is_file():raise ValueError('candidate executable missing or symlink')
  expected=pinned_executable(root,unit,UNIT_BINARIES[unit]) if unit in PINNED_UNITS else candidate
  pid=int(subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value'],text=True,timeout=5).strip())
  if pid<=0:raise ValueError('application process missing: '+unit)
  proc=proc_root/str(pid)/'exe'
  if os.readlink(proc)!=str(expected):raise ValueError('application process runs another release: '+unit)
  actual=proc.stat();expected_stat=expected.stat()
  if (actual.st_dev,actual.st_ino)!=(expected_stat.st_dev,expected_stat.st_ino):raise ValueError('application executable inode mismatch: '+unit)
  # Fence a concurrent restart between reading MainPID and observing exe.
  again=int(subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value'],text=True,timeout=5).strip())
  if again!=pid:raise ValueError('application process changed during verification: '+unit)
  if unit in PINNED_UNITS and pinned_executable(root,unit,UNIT_BINARIES[unit])!=expected:
   raise ValueError('pinned unit ExecStart changed during verification: '+unit)
  result.append({'unit':unit,'pid':pid,'executable':str(expected)})
 return {'release':release.name,'verified_application_processes':result}

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--root',required=True);parser.add_argument('--release',required=True);parser.add_argument('--units',nargs='+',required=True)
 args=parser.parse_args()
 try:print(json.dumps(verify(args.root,args.release,args.units)))
 except (OSError,ValueError,subprocess.SubprocessError) as error:raise SystemExit(str(error))
if __name__=='__main__':main()
