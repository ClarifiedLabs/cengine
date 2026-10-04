"""Engine-free RTM-081 input snapshot and prebuilt-fixture verification.

Bundles are trusted local executable inputs, not signatures. The caller pins the
manifest SHA supplied by the separately supervised build; never accept downloads.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

BUILDER = "golang@sha256:2c4c60ef415fbfa5e90300722293bef36c5e63fae17570ce18f580af933dbd73"
BUILDER_DAEMON_ID = "1af13675-8d46-4c32-8af5-e0c9b2b7fc69"
SCHEMA = "rtm081-bounded-fixture-v2"
LIMITS = {"memory": 1 << 30, "memory_swap": 1 << 30, "nano_cpus": 2000000000, "pids": 64,
          "nofile": 256, "work_tmpfs": 512 << 20, "tmp_tmpfs": 32 << 20, "network": "none", "read_only": True}
SOURCES = ("Tests/Compatibility/fixtures/managed-fuse-native.go", "Tests/Compatibility/test_managed_fuse_interrupt.py",
           "Tests/Compatibility/managed_fuse_artifact.py", "tools/build-managed-fuse-artifact.py")
BOUNDS = {"native.test": 32 << 20, "setup": 8 << 20, "mke2fs": 8 << 20, "toolchain.sha256": 4 << 20}
# RTM-085 reuses the unchanged static binary from the pinned LTP corpus build.
# This is a separate explicit local input, not a download or a build-time override.
FSX_BYTES = 780384
FSX_SHA256 = "d4293e6536e184abd383c258104765bbdec783faa7025cde93c797c97067a632"


# Closed, case-bound compile/exec/proof plan. No caller patterns or package paths.
SELECTIONS = {'RTM-104': {'case': 'RTM-104', 'binary': 'native.test', 'package': './internal/storagefuse', 'tags': [], 'test': 'TestPrepareProcessLinuxPollEINTR|TestPrepareProcessLinuxThreadMembership|TestPrepareProcessLinuxDeathRetainsDeadOwner', 'expected': ['TestPrepareProcessLinuxDeathRetainsDeadOwner', 'TestPrepareProcessLinuxPollEINTR', 'TestPrepareProcessLinuxPollEINTR/closed-owner', 'TestPrepareProcessLinuxPollEINTR/error-after-interrupt', 'TestPrepareProcessLinuxPollEINTR/exhausted-final', 'TestPrepareProcessLinuxPollEINTR/exhausted-first', 'TestPrepareProcessLinuxPollEINTR/final', 'TestPrepareProcessLinuxPollEINTR/first', 'TestPrepareProcessLinuxPollEINTR/foreign-thread', 'TestPrepareProcessLinuxPollEINTR/last-attempt', 'TestPrepareProcessLinuxPollEINTR/ready-after-interrupt', 'TestPrepareProcessLinuxPollEINTR/starttime-after-interrupt', 'TestPrepareProcessLinuxThreadMembership']},
 'RTM-107': {'case': 'RTM-107',
             'binary': 'native.test',
             'package': './internal/storagemanaged',
             'tags': [],
             'test': 'TestDurabilityPolicyHelpers|TestNativeDurabilityPolicyProcessDeath',
             'expected': ['TestDurabilityPolicyHelpers',
                          'TestNativeDurabilityPolicyProcessDeath',
                          'TestNativeDurabilityPolicyProcessDeath/barrier',
                          'TestNativeDurabilityPolicyProcessDeath/barrier/completed',
                          'TestNativeDurabilityPolicyProcessDeath/barrier/uncertain',
                          'TestNativeDurabilityPolicyProcessDeath/data',
                          'TestNativeDurabilityPolicyProcessDeath/data/completed',
                          'TestNativeDurabilityPolicyProcessDeath/data/uncertain']},
 'RTM-108': {'case': 'RTM-108',
             'binary': 'native.test',
             'package': './internal/storagemanaged',
             'tags': ['cengine_native_faulttest'],
             'test': 'TestNativeRetirementRecoveryHelpers|TestNativeRetirementRecoveryProcessDeath',
             'expected': ['TestNativeRetirementRecoveryHelpers',
                          'TestNativeRetirementRecoveryProcessDeath',
                          'TestNativeRetirementRecoveryProcessDeath/candidate',
                          'TestNativeRetirementRecoveryProcessDeath/certified',
                          'TestNativeRetirementRecoveryProcessDeath/completed',
                          'TestNativeRetirementRecoveryProcessDeath/prepared',
                          'TestNativeRetirementRecoveryProcessDeath/published']},
 'RTM-109': {'case': 'RTM-109',
             'binary': 'native.test',
             'package': './internal/storagemanaged',
             'tags': ['cengine_native_faulttest'],
             'test': 'TestNativeCopyDataRecoveryHelpers|TestNativeCopyDataRecoveryProcessDeath',
             'expected': ['TestNativeCopyDataRecoveryHelpers',
                          'TestNativeCopyDataRecoveryProcessDeath',
                          'TestNativeCopyDataRecoveryProcessDeath/cleaning-tail',
                          'TestNativeCopyDataRecoveryProcessDeath/completed-tail',
                          'TestNativeCopyDataRecoveryProcessDeath/rename',
                          'TestNativeCopyDataRecoveryProcessDeath/root-metadata',
                          'TestNativeCopyDataRecoveryProcessDeath/sealed-tail']},
 'RTM-113': {'case': 'RTM-113',
             'binary': 'native.test',
             'package': './internal/storageauthority',
             'tags': [],
             'test': 'TestNativeLifecycleCheckpointAndTerminalSeal',
             'expected': ['TestNativeLifecycleCheckpointAndTerminalSeal']},
 'RTM-110': {'case': 'RTM-110',
             'binary': 'native.test',
             'package': './internal/storagemanaged',
             'tags': ['cengine_native_faulttest'],
             'test': 'TestNativePrepareRetirementHelpers|TestNativePrepareRetirementProcessDeath',
             'expected': ['TestNativePrepareRetirementHelpers',
                          'TestNativePrepareRetirementProcessDeath',
                          'TestNativePrepareRetirementProcessDeath/completed',
                          'TestNativePrepareRetirementProcessDeath/inside-barrier',
                          'TestNativePrepareRetirementProcessDeath/published']},
 'RTM-081': {'case': 'RTM-081',
             'binary': 'native.test',
             'package': './internal/storagefuse',
             'tags': [],
             'test': 'TestNativeMountedManagedV3InterruptGraceful',
             'expected': ['TestNativeMountedManagedV3InterruptGraceful']},
 'RTM-082': {'case': 'RTM-082',
             'binary': 'native.test',
             'package': './internal/storagefuse',
             'tags': [],
             'test': 'TestNativeMountedManagedV3WriteBurstGraceful',
             'expected': ['TestNativeMountedManagedV3WriteBurstGraceful']},
 'RTM-083': {'case': 'RTM-083',
             'binary': 'native.test',
             'package': './internal/storagefuse',
             'tags': [],
             'test': 'TestNativeMountedManagedV3SparseMmapGraceful',
             'expected': ['TestNativeMountedManagedV3SparseMmapGraceful']},
 'RTM-085': {'case': 'RTM-085',
             'binary': 'native.test',
             'package': './internal/storagefuse',
             'tags': [],
             'test': 'TestNativeMountedManagedV3FsxGraceful',
             'expected': ['TestNativeMountedManagedV3FsxGraceful']},
 'RTM-087': {'case': 'RTM-087',
             'binary': 'native.test',
             'package': './internal/storagefuse',
             'tags': [],
             'test': 'TestNativeIssuedDataTLSRejectsRetiredAndPreviousServiceCredentials',
             'expected': ['TestNativeIssuedDataTLSRejectsRetiredAndPreviousServiceCredentials']},
 'RTM-089': {'case': 'RTM-089',
             'binary': 'native.test',
             'package': './internal/storagefuse',
             'tags': ['cengine_native_faulttest'],
             'test': 'TestNativeServiceFaults|TestNativeServiceFaultPlanClosed',
             'expected': ['TestNativeServiceFaultPlanClosed',
                          'TestNativeServiceFaults',
                          'TestNativeServiceFaults/stage-1-error-1',
                          'TestNativeServiceFaults/stage-1-error-2',
                          'TestNativeServiceFaults/stage-2-error-1',
                          'TestNativeServiceFaults/stage-2-error-2',
                          'TestNativeServiceFaults/stage-3-error-1',
                          'TestNativeServiceFaults/stage-3-error-2',
                          'TestNativeServiceFaults/stage-4-error-1',
                          'TestNativeServiceFaults/stage-4-error-2',
                          'TestNativeServiceFaults/stage-5-error-1',
                          'TestNativeServiceFaults/stage-5-error-2',
                          'TestNativeServiceFaults/stage-6-error-1',
                          'TestNativeServiceFaults/stage-6-error-2',
                          'TestNativeServiceFaults/stage-7-error-3']},
 'RTM-090': {'case': 'RTM-090',
             'binary': 'native.test',
             'package': './internal/storagemanaged',
             'tags': ['cengine_native_faulttest'],
             'test': 'TestNativeFaultFinalSyncTupleUnderGate',
             'expected': ['TestNativeFaultFinalSyncTupleUnderGate',
                          'TestNativeFaultFinalSyncTupleUnderGate/mutation-error-1',
                          'TestNativeFaultFinalSyncTupleUnderGate/mutation-error-2',
                          'TestNativeFaultFinalSyncTupleUnderGate/other-attachment-error-1',
                          'TestNativeFaultFinalSyncTupleUnderGate/other-attachment-error-2',
                          'TestNativeFaultFinalSyncTupleUnderGate/other-volume-error-1',
                          'TestNativeFaultFinalSyncTupleUnderGate/other-volume-error-2']},
 'RTM-091': {'case': 'RTM-091',
             'binary': 'native.test',
             'package': './internal/supervisor',
             'tags': [],
             'test': 'TestDirectExt4CopyupSymlinkDoesNotTouchTargetXattrs|TestDirectExt4SymlinkXattrsRetainPinnedIdentity|TestDirectExt4SymlinkXattrFailureRollsBack|TestDirectExt4EmptySymlinkMetadataFailureRollsBack|TestDirectExt4CopyupPartialRootXattrFailureRollsBack',
             'expected': ['TestDirectExt4CopyupPartialRootXattrFailureRollsBack',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=remove/rollback=/populated=false',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=remove/rollback=/populated=true',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=remove/rollback=set/populated=false',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=remove/rollback=set/populated=true',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=/populated=false',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=/populated=true',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=remove/populated=false',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=remove/populated=true',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=set/populated=false',
                          'TestDirectExt4CopyupPartialRootXattrFailureRollsBack/forward=set/rollback=set/populated=true',
                          'TestDirectExt4CopyupSymlinkDoesNotTouchTargetXattrs',
                          'TestDirectExt4EmptySymlinkMetadataFailureRollsBack',
                          'TestDirectExt4EmptySymlinkMetadataFailureRollsBack/ownership',
                          'TestDirectExt4EmptySymlinkMetadataFailureRollsBack/timestamps',
                          'TestDirectExt4SymlinkXattrFailureRollsBack',
                          'TestDirectExt4SymlinkXattrsRetainPinnedIdentity',
                          'TestDirectExt4SymlinkXattrsRetainPinnedIdentity/rename',
                          'TestDirectExt4SymlinkXattrsRetainPinnedIdentity/unlink']},
 'RTM-092': {'case': 'RTM-092',
             'binary': 'native.test',
             'package': './internal/storagemanaged',
             'tags': [],
             'test': 'TestSymlinkValidCapabilityXattrsMatchDirectExt4',
             'expected': ['TestSymlinkValidCapabilityXattrsMatchDirectExt4',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/nonroot-owner/get-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/nonroot-owner/list-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/nonroot-owner/remove-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/nonroot-owner/set-valid-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/root-cap-setfcap/get-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/root-cap-setfcap/list-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/root-cap-setfcap/remove-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/root-cap-setfcap/set-valid-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/uid-zero-no-caps/get-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/uid-zero-no-caps/list-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/uid-zero-no-caps/remove-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/capability-target/uid-zero-no-caps/set-valid-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/nonroot-owner/get-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/nonroot-owner/list-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/nonroot-owner/remove-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/nonroot-owner/set-valid-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/root-cap-setfcap/get-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/root-cap-setfcap/list-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/root-cap-setfcap/remove-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/root-cap-setfcap/set-valid-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/uid-zero-no-caps/get-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/uid-zero-no-caps/list-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/uid-zero-no-caps/remove-capability',
                          'TestSymlinkValidCapabilityXattrsMatchDirectExt4/missing-target/uid-zero-no-caps/set-valid-capability']},
 'RTM-093': {'case': 'RTM-093',
             'binary': 'native.test',
             'package': './internal/supervisor',
             'tags': ['cengine_native_faulttest'],
             'test': 'TestNativeIssuedPrepareInitializerPreflightV4',
             'expected': ['TestNativeIssuedPrepareInitializerPreflightV4',
                          'TestNativeIssuedPrepareInitializerPreflightV4/first-publication-fresh-attachment',
                          'TestNativeIssuedPrepareInitializerPreflightV4/positive']},
 'RTM-094': {'case': 'RTM-094',
  'binary': 'native.test',
  'package': './internal/supervisor',
  'tags': ['cengine_native_faulttest'],
  'test': 'TestNativePendingProvisionFreshMountReplayV4',
  'expected': ['TestNativePendingProvisionFreshMountReplayV4']},
 'RTM-101': {'case': 'RTM-101', 'binary': 'native.test', 'package': './internal/supervisor', 'tags': ['cengine_native_faulttest'], 'test': 'TestNativeSnapshot101DeadInitializerConsumers|TestNativeSnapshot101DirtyMmapWriteback|TestNativeSnapshot101HungAcceptedGuard|TestNativeSnapshot101PreBeginRenameUnlink|TestNativeSnapshot101ReadReaddirAtime|TestNativeSnapshot101RetainedWritableFD|TestNativeSnapshot101RuntimePoolSaturation|TestNativeSnapshot101SameUIDForeignTGID', 'expected': ['TestNativeSnapshot101DeadInitializerConsumers', 'TestNativeSnapshot101DirtyMmapWriteback', 'TestNativeSnapshot101HungAcceptedGuard', 'TestNativeSnapshot101PreBeginRenameUnlink', 'TestNativeSnapshot101ReadReaddirAtime', 'TestNativeSnapshot101RetainedWritableFD', 'TestNativeSnapshot101RuntimePoolSaturation', 'TestNativeSnapshot101SameUIDForeignTGID']},
 'RTM-095': {'case': 'RTM-095',
  'binary': 'native.test',
  'package': './internal/storagemanaged',
  'tags': [],
  'test': 'TestCopyCleanupServerCrashRestoresExactRoot|TestCopyPendingReplayFreshSessionRootBootstrap|TestPrepareExt4IdentityRealFilesystem|TestPrepareIdentityAtRejectsIntermediateSymlink',
  'expected': ['TestCopyCleanupServerCrashRestoresExactRoot',
               'TestCopyCleanupServerCrashRestoresExactRoot/after-child-unlink',
               'TestCopyCleanupServerCrashRestoresExactRoot/after-finish-before-reply',
               'TestCopyCleanupServerCrashRestoresExactRoot/after-manifest-sync',
               'TestCopyCleanupServerCrashRestoresExactRoot/after-root-sync',
               'TestCopyCleanupServerCrashRestoresExactRoot/after-transaction-unlink',
               'TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-child-unlink',
               'TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-finish-before-reply',
               'TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-manifest-sync',
               'TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-root-sync',
               'TestCopyCleanupServerCrashRestoresExactRoot/sealed/after-transaction-unlink',
               'TestCopyPendingReplayFreshSessionRootBootstrap',
               'TestPrepareExt4IdentityRealFilesystem',
               'TestPrepareIdentityAtRejectsIntermediateSymlink']},
 'RTM-102': {'case': 'RTM-102',
 'binary': 'native.test',
 'package': './internal/storagemanaged',
 'tags': ['cengine_native_faulttest'],
 'test': 'TestNativePrepareIdentity102AuthorityJournal|TestNativePrepareIdentity102CrossFilesystem|TestNativePrepareIdentity102ForgetRelookup|TestNativePrepareIdentity102LargeManifestRecovery|TestNativePrepareIdentity102ManifestAuthenticity|TestNativePrepareIdentity102PublicationAuthenticity|TestNativePrepareIdentity102RegisteredRootReuse|TestNativePrepareIdentity102Reuse|TestNativePrepareIdentity102SameNameVolume|TestPrepareManifestPreserves64MiBBoundWithStreamingDigest',
 'expected': ['TestNativePrepareIdentity102AuthorityJournal',
              'TestNativePrepareIdentity102AuthorityJournal/exact-operation',
              'TestNativePrepareIdentity102AuthorityJournal/exact-operation/target',
              'TestNativePrepareIdentity102AuthorityJournal/foreign-operation',
              'TestNativePrepareIdentity102AuthorityJournal/foreign-operation/source',
              'TestNativePrepareIdentity102AuthorityJournal/foreign-operation/target',
              'TestNativePrepareIdentity102AuthorityJournal/foreign-state',
              'TestNativePrepareIdentity102AuthorityJournal/foreign-state/source',
              'TestNativePrepareIdentity102AuthorityJournal/foreign-state/target',
              'TestNativePrepareIdentity102AuthorityJournal/stale-operation',
              'TestNativePrepareIdentity102AuthorityJournal/stale-operation/advance',
              'TestNativePrepareIdentity102AuthorityJournal/stale-operation/target',
              'TestNativePrepareIdentity102CrossFilesystem',
              'TestNativePrepareIdentity102ForgetRelookup',
              'TestNativePrepareIdentity102LargeManifestRecovery',
              'TestNativePrepareIdentity102ManifestAuthenticity',
              'TestNativePrepareIdentity102ManifestAuthenticity/altered',
              'TestNativePrepareIdentity102ManifestAuthenticity/copied',
              'TestNativePrepareIdentity102ManifestAuthenticity/late-uncertain',
              'TestNativePrepareIdentity102PublicationAuthenticity',
              'TestNativePrepareIdentity102PublicationAuthenticity/all-published',
              'TestNativePrepareIdentity102PublicationAuthenticity/all-published/digest',
              'TestNativePrepareIdentity102PublicationAuthenticity/all-published/handle',
              'TestNativePrepareIdentity102PublicationAuthenticity/all-published/late-uncertain',
              'TestNativePrepareIdentity102PublicationAuthenticity/all-published/path',
              'TestNativePrepareIdentity102PublicationAuthenticity/all-published/root-metadata',
              'TestNativePrepareIdentity102PublicationAuthenticity/all-published/valid',
              'TestNativePrepareIdentity102PublicationAuthenticity/first-published',
              'TestNativePrepareIdentity102PublicationAuthenticity/first-published/digest',
              'TestNativePrepareIdentity102PublicationAuthenticity/first-published/handle',
              'TestNativePrepareIdentity102PublicationAuthenticity/first-published/late-uncertain',
              'TestNativePrepareIdentity102PublicationAuthenticity/first-published/path',
              'TestNativePrepareIdentity102PublicationAuthenticity/first-published/root-metadata',
              'TestNativePrepareIdentity102PublicationAuthenticity/first-published/valid',
              'TestNativePrepareIdentity102PublicationAuthenticity/private',
              'TestNativePrepareIdentity102PublicationAuthenticity/private/digest',
              'TestNativePrepareIdentity102PublicationAuthenticity/private/handle',
              'TestNativePrepareIdentity102PublicationAuthenticity/private/late-uncertain',
              'TestNativePrepareIdentity102PublicationAuthenticity/private/path',
              'TestNativePrepareIdentity102PublicationAuthenticity/private/root-metadata',
              'TestNativePrepareIdentity102PublicationAuthenticity/private/valid',
              'TestNativePrepareIdentity102RegisteredRootReuse',
              'TestNativePrepareIdentity102RegisteredRootReuse/capture',
              'TestNativePrepareIdentity102Reuse',
              'TestNativePrepareIdentity102Reuse/file',
              'TestNativePrepareIdentity102Reuse/root',
              'TestNativePrepareIdentity102SameNameVolume',
              'TestPrepareManifestPreserves64MiBBoundWithStreamingDigest']}}


def selection(case_id):
    require(type(case_id) is str and case_id in SELECTIONS, "closed native case required")
    return json.loads(encode(SELECTIONS[case_id]))


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "SHA256 required")
    return value


def approved_daemon_id(value):
    require(isinstance(value, str) and value == BUILDER_DAEMON_ID, "exact approved builder daemon UUID required")
    return value


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def read_file(root, name, maximum, *, private=False, allow_empty=False):
    require(isinstance(name, str) and name and not name.startswith("/") and
            all(p not in ("", ".", "..") for p in name.split("/")), "relative input path required")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in name.split("/")[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        leaf = name.split("/")[-1]
        source = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        with os.fdopen(source, "rb") as stream:
            before = os.fstat(source)
            require(stat.S_ISREG(before.st_mode) and (0 if allow_empty else 1) <= before.st_size <= maximum, "bounded regular input required")
            if private:
                require(before.st_uid == os.geteuid() and before.st_nlink == 1 and not before.st_mode & 0o022,
                        "private owned fixture file required")
            raw = stream.read(maximum + 1)
            require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(source)) ==
                    stamp(os.stat(leaf, dir_fd=fd, follow_symlinks=False)), "input changed during read")
            return raw
    finally:
        os.close(fd)


def snapshot(root):
    root = Path(root)
    names = list(SOURCES)
    for directory, dirs, files in os.walk(root / "Guest", followlinks=False):
        require(not any((Path(directory) / d).is_symlink() for d in dirs), "source directory link")
        for name in files:
            path = Path(directory) / name
            require(path.suffix != ".syso", "unrecorded Go object input forbidden")
            if path.suffix in {".go", ".s", ".S", ".h", ".c", ".mod", ".sum"} or name == "modules.txt":
                names.append(str(path.relative_to(root)))
    require(0 < len(names) <= 20000, "source count bound")
    result, used = {}, 0
    for name in sorted(names):
        raw = read_file(root, name, 8 << 20, allow_empty=True)
        require(not name.endswith(".go") or b"//go:embed" not in raw, "unrecorded Go embed input forbidden")
        used += len(raw); require(used <= 128 << 20, "source aggregate bound")
        result[name] = raw
    return result


def inventory(root):
    return {name: digest(raw) for name, raw in snapshot(root).items()}


def static_arm64(raw):
    require(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", raw, 18)[0] == 183,
            "Linux arm64 ELF required")
    offset, size, count = struct.unpack_from("<Q", raw, 32)[0], struct.unpack_from("<H", raw, 54)[0], struct.unpack_from("<H", raw, 56)[0]
    require(size == 56 and 0 < count <= 128 and offset + size * count <= len(raw), "ELF program headers")
    require(all(struct.unpack_from("<I", raw, offset + size * n)[0] != 3 for n in range(count)), "static ELF required")


def validate_fsx(raw):
    require(type(raw) is bytes and len(raw) == FSX_BYTES and digest(raw) == FSX_SHA256,
            "exact pinned fsx binary required")
    static_arm64(raw)
    return raw


def load_fsx(path):
    require(type(path) is str and 0 < len(os.fsencode(path)) <= 4096 and path.startswith("/") and
            all(part not in ("", ".", "..") for part in path[1:].split("/")) and
            not any(ord(c) < 32 or ord(c) == 127 for c in path), "explicit absolute fsx input required")
    # Walk every component without following links; reject devices, writable or
    # multi-link inputs before reading. Hash validation precedes OCI publication.
    return validate_fsx(read_file("/", path[1:], FSX_BYTES, private=True))


def toolchain_proof(raw):
    require(0 < len(raw) <= BOUNDS["toolchain.sha256"], "toolchain manifest bound")
    require(raw.endswith(b"\0"), "NUL-delimited toolchain inventory required")
    rows = raw[:-1].split(b"\0")
    require(100 < len(rows) <= 30000, "full Go distribution inventory required")
    paths = []
    for row in rows:
        require(re.fullmatch(rb"[0-9a-f]{64}", row[:64]) and row[64:66] == b"  " and
                row[66:].startswith(b"/usr/local/go/"), "toolchain inventory row")
        path = row[66:]
        require(b".." not in path.split(b"/"), "toolchain path traversal")
        paths.append(path)
    require(paths == sorted(set(paths)) and {b"/usr/local/go/bin/go", b"/usr/local/go/pkg/tool/linux_arm64/compile",
            b"/usr/local/go/pkg/tool/linux_arm64/asm", b"/usr/local/go/pkg/tool/linux_arm64/link"} <= set(paths), "full toolchain binaries required")
    return {"sha256": digest(raw), "files": len(rows)}


def load_fixture(directory, expected_sha, root, case_id="RTM-081"):
    selected = selection(case_id)
    directory = Path(directory)
    info = os.stat(directory, follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022, "private fixture directory")
    raw = read_file(directory, "fixture.json", 512 << 10, private=True)
    require(digest(raw) == sha(expected_sha), "fixture manifest pin mismatch")
    value = json.loads(raw, object_pairs_hook=object_pairs)
    require(set(value) == {"schema", "sources", "builder", "binaries", "toolchain", "cleanup", "formatter_sha256", "selection"} and
            value["schema"] == SCHEMA, "fixture schema")
    require(value["selection"] == selected, "fixture case/package/tag/selector proof")
    require(value["sources"] == inventory(root), "fixture source inventory mismatch")
    build = value["builder"]
    require(set(build) == {"reference", "image_id", "daemon_id", "limits", "exit", "oom", "container", "crosscompiled"} and
            build["reference"] == BUILDER and build["limits"] == LIMITS and type(build["exit"]) is int and
            build["exit"] == 0 and build["oom"] is False and build["crosscompiled"] == ["arm64", "amd64"], "bounded builder proof")
    sha(build["image_id"].removeprefix("sha256:")); approved_daemon_id(build["daemon_id"]); sha(build["container"])
    require(build["image_id"].startswith("sha256:"), "approved cached builder identity")
    require(value["cleanup"] == {"container": build["container"], "removed": True}, "builder cleanup proof")
    require(set(value["binaries"]) == {"native.test", "setup", "mke2fs"}, "fixture binary names")
    files = {}
    for name in BOUNDS:
        files[name] = read_file(directory, name, BOUNDS[name], private=True)
        if name != "toolchain.sha256":
            require(value["binaries"][name] == {"sha256": digest(files[name]), "bytes": len(files[name])}, "binary provenance mismatch")
            static_arm64(files[name])
    require(value["toolchain"] == toolchain_proof(files["toolchain.sha256"]), "toolchain provenance mismatch")
    require(value["formatter_sha256"] == digest(files["mke2fs"]), "formatter pin mismatch")
    return value, files
