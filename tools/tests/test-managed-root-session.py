#!/usr/bin/env python3
"""Bounded host-only joined RTM103 Session regression. No native/mount actions.

The Go overlay exposes test-only credential and file-executor adapters without
adding a capability constructor or a test hook to any shipped guest package.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--registration', action='store_true', help='run joined registration control cases')
parser.add_argument('--work', type=Path, required=True, help='external cache/temp directory')
args = parser.parse_args()
work = args.work.resolve()
if not str(work).startswith('/Volumes/data/'):
    parser.error('--work must be external /Volumes/data storage')
work.mkdir(parents=True, exist_ok=True)
fixtures = ROOT / 'tools/tests/fixtures'
overlay = {'Replace': {
    str(ROOT / 'Guest/internal/storageclient/zz_rtm103_host.go'): str(fixtures / 'rtm103-root-client.gotxt'),
    str(ROOT / 'Guest/internal/storageserver/zz_rtm103_host.go'): str(fixtures / 'rtm103-root-server.gotxt'),
    str(ROOT / 'Guest/internal/workloadstorage/zz_rtm103_joined_test.go'): str(fixtures / 'rtm103-root-session.gotxt'),
}}
path = work / 'overlay.json'
path.write_text(json.dumps(overlay, indent=2) + '\n')
env = dict(os.environ)
for key, subdir in [('GOCACHE', 'cache'), ('GOTMPDIR', 'tmp'), ('TMPDIR', 'tmp')]:
    directory = work / subdir
    directory.mkdir(exist_ok=True)
    env[key] = str(directory)
subprocess.run(['go', 'test', '-race', '-count=1', '-timeout=90s', '-tags=cengine_prepare_full_compat',
                '-overlay', str(path), './internal/workloadstorage', '-run', '^TestOriginalRegistrationJoinedSession$' if args.registration else '^TestOriginalRootJoinedSession$', '-v'],
               cwd=ROOT / 'Guest', env=env, check=True, timeout=120)
