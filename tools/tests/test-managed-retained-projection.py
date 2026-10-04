#!/usr/bin/env python3
"""Joined finite proof projection fixtures; never native acceptance."""
import copy
from pathlib import Path
import runpy
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import managed_stale_consumer as s
import managed_retained_backing as backing
values = runpy.run_path(str(ROOT / 'tools/tests/test-managed-stale-consumer.py'))['values']
positive_backing = runpy.run_path(str(ROOT / 'tools/tests/test-managed-retained-backing.py'))['positive']


def fixture(same=True):
    value, b, intent, boot = values('same-e-existing-data' if same else s.IMPLEMENTED)
    case = backing.FD_CASES[0 if same else 1]
    b.update(version=7 if same else 5, caseName=case)
    o, worker = value['original'], value['worker']
    o['arm'].update(version=b['version'], caseName=case)
    o.pop('rootRequest', None)
    o.update(fdOperation='write-file-fsync', fdSequence=2,
        originalOperation=dict(kind='write-file-fsync', sequence=2, errorClass='transport-failed' if same else 'mount-closed-joined'))
    if same: o['stage'] = 'original-file-attempt'; worker['query'].update(version=8, caseName=case)
    prior_write = dict(node=19, handle=23, requestSequence=2)
    prior_sync = dict(node=19, handle=23, requestSequence=3)
    capability = dict(node=19, requestSequence=4)
    o['writable'] = dict(identitySHA256='3'*64, written=0, writeError='eio', syncError='enotconn', completed=True)
    if same:
        o['writable']['trace'] = dict(capability=capability, writeOK=False, syncOK=False)
        worker['evidence']['admission'] = dict(original=copy.deepcopy(worker['query']['original']), **capability,
            operation='get_xattr', authKind=1, noHandle=True, capabilityName='security.capability')
    positive = copy.deepcopy(o)
    positive.update(stage='begun', scope=copy.deepcopy(b['scope']), serverDERSHA256='', signCount=0, signInputSHA256='',
        bytesWrittenAfterSign=0, clientWrittenBytes=0, clientPrefixBytes=0, clientPrefixSHA256='', localError='', fdSequence=1,
        originalOperation=dict(kind='write-file-fsync', sequence=1, errorClass='ok'),
        writable=dict(identitySHA256='3'*64, written=1, writeError='ok', syncError='ok', completed=True,
            trace=dict(write=prior_write, sync=prior_sync, writeOK=True, syncOK=True)))
    ack = backing.baseline_marker(b, str(uuid.uuid4()), str(uuid.uuid4()), '8'*64, positive_backing())
    value.update(positive=positive, baseline=ack)
    # Observed JSON and independently retained owner inputs must not alias.
    return tuple(copy.deepcopy(item) for item in (value, b, intent, boot, ack))


class ProjectionTests(unittest.TestCase):
    def check(self, args): return s.correlated_result(*args)
    def test_both_complete_chains_and_selectors_source_enabled_only(self):
        for same in (True, False):
            args = fixture(same); self.assertEqual(self.check(args), args[0])
            selected = s.selection(s.p.FULL_PROFILE, s.CASES, args[1]['caseName'])
            self.assertFalse(selected['fullAcceptance'])
            self.assertEqual(selected['coverage'], '1/18')

    def test_every_observed_object_has_closed_required_shape(self):
        def objects(value, path=()):
            if isinstance(value, dict):
                yield path, value
                for key, item in value.items(): yield from objects(item, (*path, key))
        checked = 0
        for same in (True, False):
            base = fixture(same)
            for path, obj in objects(base[0]):
                for field in obj:
                    for mutation in ('missing', 'null'):
                        args = copy.deepcopy(base); target = args[0]
                        for key in path: target = target[key]
                        if mutation == 'missing': del target[field]
                        else: target[field] = None
                        with self.subTest(same=same, path=path, field=field, mutation=mutation), self.assertRaises((ValueError, KeyError)):
                            self.check(args)
                        checked += 1
                args = copy.deepcopy(base); target = args[0]
                for key in path: target = target[key]
                target['unrecognized'] = 'not-authority'
                with self.subTest(same=same, path=path), self.assertRaises(ValueError): self.check(args)
        self.assertGreater(checked, 500)

    def test_json_numbers_never_alias_boolean_or_fractional_witnesses(self):
        def numbers(value, path=()):
            if isinstance(value, dict):
                for key, item in value.items(): yield from numbers(item, (*path, key))
            elif type(value) in (int, bool): yield path, value
        for same in (True, False):
            base = fixture(same)
            for path, value in numbers(base[0]):
                for bad in ((int(value),) if type(value) is bool else (float(value), bool(value))):
                    args = copy.deepcopy(base); target = args[0]
                    for key in path[:-1]: target = target[key]
                    target[path[-1]] = bad
                    with self.subTest(same=same, path=path, wrong=bad), self.assertRaises(ValueError): self.check(args)

    def test_positive_success_matches_actual_guest_and_swift_contract(self):
        guest = (ROOT / 'Guest/internal/workloadstorage/original_writable.go').read_text()
        swift = (ROOT / 'Sources/CEngineCore/OriginalConsumerObservationProtocol.swift').read_text()
        self.assertIn('return "ok"', guest)
        self.assertIn('writable.writeError == "ok", writable.syncError == "ok"', swift)
        for field in ('writeError', 'syncError'):
            for wrong in ('', 'eio', None, True):
                args = fixture(); args[0]['positive']['writable'][field] = wrong
                with self.subTest(field=field, wrong=wrong), self.assertRaises(ValueError): self.check(args)

    def test_missing_positive_backing_or_any_original_field_rejected(self):
        for same in (True, False):
            base = fixture(same)
            for section in ('original', 'positive'):
                for field in base[0][section]:
                    args = copy.deepcopy(base); del args[0][section][field]
                    with self.subTest(same=same, section=section, field=field), self.assertRaises((ValueError, KeyError)):
                        self.check(args)
            for field in ('positive', 'baseline'):
                args = copy.deepcopy(base); del args[0][field]
                with self.assertRaises(ValueError): self.check(args)

    def test_wrong_original_operation_identity_or_positive_cannot_substitute(self):
        for same in (True, False):
            for section, field, changed in (('original', 'fdOperation', 'fsync-directory'),
                    ('original', 'fdSequence', True), ('positive', 'fdSequence', True),
                    ('original', 'mountIdentitySHA256', '9'*64), ('positive', 'stage', 'armed-mounted-positive')):
                args = fixture(same); args[0][section][field] = changed
                with self.subTest(same=same, field=field), self.assertRaises(ValueError): self.check(args)
            for field, changed in (('written', 1), ('written', False), ('completed', 1), ('writeError', ''), ('syncError', ''), ('identitySHA256', '9'*64)):
                args = fixture(same); args[0]['original']['writable'][field] = changed
                with self.subTest(same=same, field=field), self.assertRaises(ValueError): self.check(args)

    def test_exact_admission_retirement_and_monotonic_sequence(self):
        for field, changed in (('node', 20), ('handle', 24), ('requestSequence', 3), ('authKind', 3),
                ('operation', 'fsync'), ('noHandle', 1), ('capabilityName', 'user.capability'), ('writeOneAtZero', True)):
            args = fixture(); args[0]['worker']['evidence']['admission'][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError): self.check(args)
        args = fixture(); args[0]['original']['writable']['trace']['capability']['requestSequence'] = 3
        with self.assertRaises(ValueError): self.check(args)
        args = fixture(); args[0]['retirement']['operation'] = str(uuid.uuid4())
        with self.assertRaises(ValueError): self.check(args)
        args = fixture(); args[0]['positive']['writable']['trace']['sync']['handle'] += 1
        with self.assertRaises(ValueError): self.check(args)

    def test_cross_e_local_failure_is_not_fabricated_admission(self):
        args = fixture(False); args[0]['original']['writable']['trace'] = dict(writeOK=False, syncOK=False)
        with self.assertRaises(ValueError): self.check(args)
        args = fixture(False); args[0]['original']['clientPrefixSHA256'] = '9'*64
        with self.assertRaises(ValueError): self.check(args)
        args = fixture(False); args[0]['original']['originalOperation']['errorClass'] = 'transport-failed'
        with self.assertRaises(ValueError): self.check(args)


if __name__ == '__main__': unittest.main()
