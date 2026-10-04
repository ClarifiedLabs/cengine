#!/usr/bin/env python3
"""Offline canonical-claim adapters: no engine, helper, native job or real claim.

Run: python3 tools/tests/test-tool-canonical-claims.py
"""
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PRUNE = load('volume_reference_prune')
BUILD = load('build-managed-fuse-artifact')
UNITS = load('test-guest-unit-bounded')
CLAIMS = PRUNE.claims
ADAPTERS = (PRUNE.ParentLock, BUILD.OriginalLock, UNITS.OriginalLock)


class CanonicalClaimTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.lock = self.root / 'claim'
        self.lock.mkdir(mode=0o700)
        (self.lock / 'pid').write_text(str(os.getppid()) + '\n')
        (self.lock / 'pid').chmod(0o600)
        # Keep the real shared launcher policy; substitute host discovery only.
        for context in (
            patch.dict(os.environ, {'HOME': str(self.root)}, clear=True),
            patch.object(CLAIMS.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(self.root))),
            patch.object(CLAIMS, 'canonical_temp', return_value=Path(tempfile.gettempdir()).resolve()),
            patch.object(CLAIMS.subprocess, 'run', side_effect=AssertionError('no native commands')),
        ):
            context.start()
            self.addCleanup(context.stop)

    def test_default_is_shared_per_uid_not_ambient_tmpdir_or_home(self):
        for uid in (501, 502):
            with patch.object(CLAIMS.os, 'getuid', return_value=uid), \
                    patch.dict(os.environ, TMPDIR='/competing', CENGINE_COMPAT_LOCK='/competing/claim'):
                self.assertEqual(CLAIMS.canonical_lock(), Path(f'/private/tmp/cengine-compat-run-{uid}.lock'))

    def test_all_adapters_accept_default_or_matching_environment_without_acquiring(self):
        with patch.object(CLAIMS, 'canonical_lock', return_value=self.lock):
            for adapter in ADAPTERS:
                for environment in ({}, {'CENGINE_COMPAT_LOCK': str(self.lock)}):
                    with self.subTest(adapter=adapter, environment=environment), patch.dict(os.environ, environment):
                        lock = adapter(self.lock, os.getppid())
                        try:
                            lock.check()
                        finally:
                            if hasattr(lock, 'close'):
                                lock.close()
                        self.assertEqual(list(self.lock.iterdir()), [self.lock / 'pid'])

    def test_competing_environment_rejected_even_when_argument_matches(self):
        with patch.object(CLAIMS, 'canonical_lock', return_value=self.root / 'canonical'), \
                patch.dict(os.environ, CENGINE_COMPAT_LOCK=str(self.lock)):
            for adapter in ADAPTERS:
                with self.subTest(adapter=adapter), self.assertRaisesRegex(RuntimeError, 'canonical owner lock'):
                    adapter(self.lock, os.getppid())
        self.assertTrue((self.lock / 'pid').is_file())

    def test_old_global_and_other_uid_paths_rejected(self):
        with patch.object(CLAIMS, 'canonical_lock', return_value=self.root / f'cengine-compat-run-{os.getuid()}.lock'):
            for name in ('cengine-compat-run.lock', f'cengine-compat-run-{os.getuid() + 1}.lock'):
                other = self.root / name
                other.mkdir(mode=0o700)
                (other / 'pid').write_text(str(os.getppid()) + '\n')
                for adapter in ADAPTERS:
                    with self.subTest(adapter=adapter, name=name), self.assertRaises((ValueError, PRUNE.ref.Refusal)):
                        adapter(other, os.getppid())


if __name__ == '__main__':
    unittest.main()
