# Original PID1 consumer observer

## Integration contract

The full-profile observer provides native selectors; see
[docs/docker-compatibility.md](../../../docs/docker-compatibility.md) for scoped
RTM-103 acceptance. Observation receipts do not confer authority. Writable-FD
versions and exact Linux close semantics are described in [RETAINED-FD.md](RETAINED-FD.md).

Root READ recording permits at most one same-object GETATTR immediately before
the actual READ. The reply must describe the same regular-file inode and fixed
32-byte size; any handle must match the READ. READ must succeed with 32 actual
bytes on the immediately following sequence, using the same node owner. A
metadata-only/cache-only window, duplicate or later metadata, unrelated traffic,
wrong node/handle, errno, unjoined calls or bad reply remains a failure. The
witness is always the real READ, never the metadata prelude.

The only production observer constructor is private to `nativeFactory`, enabled when the
exclusive compile profile is `preparecompat.FullProfile` (`rtm096-full-nine-v3`).
The signed image/owner validation remains the existing host/shim responsibility.

The existing host-only CID2 control server holds its managed `Server` before
listeners start. Its exact observer commands are dispatched before ordinary
workload methods, including after storage-session termination. There is no new
listener, public credential constructor, arbitrary mount path or dial address.

## Closed version/case selection

`OriginalConsumerArm.valid` accepts only these combinations:

| Version | Cases |
|---|---|
| 1 | Cross-E old-leaf reconnect, existing DATA and directory retained-FD |
| 2 | Wrong-hello cases selected by `WrongHelloCase` |
| 3 | Cross-E existing DATA with a matching positive root GETATTR |
| 4 | Same-E existing DATA/reconnect and attachment-key-reuse/delayed-registration |
| 5 | Writable retained-FD cases |
| 6 | Root-grant cases |
| 7 | Same-E writable retained-FD with the exact prewrite-denial witness |

Same-E checks use the retained original client and actual request/admission
correlation, not cross-E local closed-client rejection. Writable and root-grant
cases retain their original descriptors and require independent backing checks.
No selector can replace a required mounted positive or actual negative with a
receipt, timeout or fabricated credential.

## Shared JSON and version-1 command contract

All named fields are required, exact-case; duplicates, unknown fields, nulls and
trailing input fail. Binary public `Peer` DER uses the existing base64 encoding.

`Arm` = `{version, profile:"rtm096-full-nine-v3", requestID:UUID,
operationUUID:UUID, caseName, binding:BootBinding, scope:Scope,
targetAttachment:UUID, leafSHA256:lowercaseSHA256}`.

The command behavior below describes version 1; later versions require the
case-specific positives and evidence above in addition to shared binding checks.

* `original-consumer-arm`: Arm. Must match the actual installed RUNNING runtime
  session, boot, scope, key, leaf and real mounted attachment. Opens/FSYNCDIRs the
  actual mount, then opens and retains the original directory FD; validates FUSE,
  statx mount/device/inode identity, and performs a second FSYNCDIR. Returns stage
  `armed-mounted-positive` and only a digest of stat identity/key fingerprint.
* `original-consumer-begin`: identical Arm. Starts one fixed monotonic ten-second
  budget, returning `begun`; neither retries nor queries extend it.
* `original-consumer-probe`: `{arm:Arm, scope:Scope, peer:Peer}`. One attempt only.
  Peer address must remain the original sealed address; port remains 2049.
  `scope` preserves all original fields except adopted service/controller fields.
  The exact current peer must come from owner-sealed maintenance, not queue trust.
* `original-consumer-result`: `{arm:Arm, serverPrefixBytes:uint64,
  serverPrefixSHA256:lowercaseSHA256}`. Exactly one query, after the worker has
  attributed its actual TLS certificate-verification/unknown-CA failure to this
  exact old leaf. Checks bounds and computes
  `SHA256(storageserver.TLSFailurePrefixDomain || first N actually written bytes)`.
  The shared server constant is `cengine/storageserver/tls-failure-read-prefix/v1\0`
  (including the trailing NUL); an unseparated raw-prefix hash is rejected.
* `original-consumer-release`: identical Arm. Cancels and closes the exact owned
  socket first, joins the active probe, releases FD/private state and returns
  `{arm:Arm,stage:"released"}`. Safe to join again for the same arm. It never means
  successful drain or releases shim quarantine/reconciliation/containment.

Arm/begin/probe/result return `OriginalConsumerEvidence` (see JSON tags in
`original_consumer.go`). Common fields include zero/empty values; optional
`roots`, `writable`, `rootRequest` and `hello` are version/case-specific.
`stage`, `scope`, `keySHA256`, `mountIdentitySHA256`, `serverDERSHA256`, `signCount`,
`signInputSHA256`, `bytesWrittenAfterSign`, `clientWrittenBytes`,
`clientPrefixBytes`, `clientPrefixSHA256`, `localError`, `fdOperation`, `fdSequence`,
`originalOperation` (required exact object `{kind,sequence,errorClass}`)
are observations, not caller-supplied receipts. `fdSequence` is the local observer
operation sequence, **not** a storagewire request sequence. No `success` boolean,
FD number, signature, private key or ciphertext is exported.

## Version-1 evidence limits

* `cross-e-old-leaf-reconnect`: the retained original identity is forced despite
  successor CA hints; normal PKI + exact server DER verification and TLS 1.3 full
  handshake/no resumption remain mandatory. A private signer witnesses exactly
  one real CertificateVerify and subsequent actual writes. At most 128KiB of
  client-to-server ciphertext is retained privately, zeroed on release. Initial
  result stage is `original-owner-signed-flight`; only the later prefix query
  gives `original-owner-prefix-correlated`. EOF alone never supplies evidence of
  server rejection. This is owner-attested key use, **not** server verification of
  CertificateVerify on a rejected chain.
* `cross-e-retained-fd`: wait for the original mount's real `Done` join and
  non-nil terminal reason, then FSYNCDIR the same original FD. Only
  EIO/ENOTCONN/ESTALE/EACCES produce the typed `originalOperation` kind
  `fsync-directory`, sequence 2, errorClass `eio`/`enotconn`/`estale`/`eacces`.
  Success, timeout, unjoined mount, clean closure or other errors fail.
* `cross-e-existing-data`: through the exact retained native attachment/client,
  verify its full original DATA authority tuple and actual client worker join,
  then require its normal `Do` root GETATTR path to reject with typed ErrClosed.
  No valid credential snapshot is fabricated; terminal admission precedes all
  credentials and remains sticky. No writer/client is added on the old TLS conn.
  The typed `originalOperation` is `data-getattr-root`, sequence 1, errorClass
  `client-closed-joined`. This is local closed-client rejection, NOT an authority
  Admit/authentication denial. The positive real mounted fsync remains mandatory.
* Both cross-E cases ALSO perform the unchanged old-leaf TLS flight and
  require worker-attributed prefix correlation. Stages remain
  `original-owner-signed-flight` then `original-owner-prefix-correlated`;
  `localError` retains only the TLS result. Arm/Begin and old-leaf-only return
  `{kind:"",sequence:0,errorClass:""}`.
* Version 1 rejects same-E, PREPARE and other inventory cases. Retire fences
  authority and joins admitted guards/barrier, but does not close the DATA
  transport or join the native mount. Retained-FD success cannot be based on a
  retirement receipt alone; no timing/death shortcut is permitted. Unsupported
  version/case combinations are rejected.

Owner expiry/explicit release closes the one owned TLS socket, joins the attempt
and releases the FD. A lost CID2 connection cannot extend the owner budget. The
host must independently hold/release its exact shim observation lease and ALWAYS
perform mandatory containment, including on malformed evidence and timeout.

## Verification boundary

Host tests cover real fresh-CA TLS rejection, forced old leaf, original signer,
fragmented read-prefix correlation paired with actual DATA `Server.Serve` /
`TLSFailureEvidence`, unseparated-hash rejection, closed schema, one-shot query, exact peer,
fixed budget, concurrent release/join and private capture overflow. Linux/arm64
cross-compilation does not execute mounted FUSE positives, post-retire FD
negatives or signed-shim arbitration; those require their own native checks.

## Matching DATA positive (version 3)

Version 3 is accepted only for `cross-e-existing-data`; v1/v2 shapes and evidence
semantics are distinct from its matching positive. Arm verifies the
native FUSE mount, then `Mounted.OriginalConsumerPositiveRoot` uses its exact
`storageclient.Client.OriginalConsumerPositiveRoot`: fixed root GETATTR through
Client.Do/FIFO/TLS/Authority.Admit, under full DataHello equality. Its private
metadata-only snapshot uses the issued root grant, NOT captured kernel caller
credentials. No UID/PID, writable authority or snapshot is exported. A successful
GETATTR reply for the original directory inode is required; cached stat, handshake,
FSYNCDIR and encoded observations cannot supply it. Cancellation fails the exact
client through normal terminal cleanup and joins it; never yields evidence.
Arm/Begin emit `originalOperation={kind:"data-getattr-root",sequence:1,errorClass:"ok"}`.
Probe/Result emit the same kind with sequence2/errorClass `client-closed-joined`,
only after original mount/client join. This is LOCAL rejection, not server denial.
The host must validate both observations before sealing.

WrongV v2 requires exactly two installed issued live mounted runtime entries,
distinct volume/key/leaf, with smallest attachment UUID as original. Missing/dead
alternative, conflicting third runtime and non-primary target fail closed;
PREPARE entries do not count. WrongMode retains the real RO original requirement;
writer positives belong to the paired fixture.
