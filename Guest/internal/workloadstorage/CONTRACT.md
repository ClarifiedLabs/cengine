# Workload storage wire v1

This document freezes the **wire codec** in `wire.go`; decoding alone confers no
authority. `session.go` implements the one-shot managed lifecycle, while
`native_linux.go` activates it only from committed container boot evidence and
the immutable managed kernel mode. Port 4109 is not available without that
committed evidence.

## Envelope and framing

Private namespace `workload-storage.v1`, version `1`, control port **4109**.
Each frame is a nonzero **uint32 big-endian** body length followed by that many
UTF-8 JSON bytes, at most **1 MiB**. Every envelope has exactly
`version`, `type`, `operation`, `binding`, `data`; every operation except the
binding-only `hello` additionally requires `scope`. `hello` forbids scope. Only `command` and
`reply` additionally require `sequence` (uint64 > 0) and `kind`.

`binding = {shimLaunchUUID, guestBootNonce}` (UUIDv4).
`scope = {intent, store, serviceEpoch, controllerEpoch, controllerKey, container,
containerInstance, launch, prepare, specificationDigest}`. Epoch is uint64 > 0;
controllerKey, container (Docker ID), and specificationDigest are 64 lowercase
hex characters. Other scope fields are UUIDv4. Every scoped frame requires
`binding.shimLaunchUUID == scope.launch`. UUID text is canonical lowercase,
non-nil, hyphenated; fields specified as UUIDv4 enforce version and variant.

JSON is closed: reject unknown/missing fields, duplicate keys (including escaped
aliases), null anywhere, trailing JSON, invalid UTF-8, unpaired escaped UTF-16
surrogates, noncanonical unsigned integers, and noncanonical standard padded
base64. Maximum nesting depth is 8 (root zero); every array is bounded to 64
before DTO decoding. Public DTOs are `Frame`, `Payload`, `BootBinding`, `Scope`,
`Peer`, `Slot`, `MountBinding`, and `Offer`. Payload pointer fields distinguish
absence from explicit empty arrays, empty ioClaim, and false booleans.

## Exact payloads

| Operation / kind | Exact `data` fields |
| --- | --- |
| hello (no scope) | `{}` |
| configure | `peer`, `mounts`, `slots` |
| configured | `{}` |
| command / offer-keys, mount-phase, close-phase | `role` |
| command / install-certificate | `attachment`, `certificateDER` |
| command / prepare | `workloadJSON`, `ioClaim` |
| command / start, status, abort | `{}` |
| reply / offer-keys | `offers` |
| reply / install-certificate | `attachment` |
| reply / mount-phase | `attachmentIDs` |
| reply / prepare | `prepare`, `containerInstance`, `launch`, `succeeded`, `cleanCopyUp`, `evidenceDigest` |
| reply / close-phase | `role`, `attachmentIDs`, `clean` |
| reply / start | `status: "running"`, `pid` |
| reply / status | `phase`, `mountedIDs`, `terminalIDs` |
| reply / abort | `terminalIDs` |
| reply / any kind, error | `code` only |
| terminal | nonempty `attachmentIDs`, `code` |

Roles: `prepare`, `runtime`. Modes: `read-only`, `read-write`.
PID is uint32 in 1...2147483647. Prepare reply identity fields must exactly match
scope; evidenceDigest is 64 lowercase hex. Offers are at most 64 objects
`{attachment, key, csrDER}`, with unique UUIDv4 attachments, 64-lowerhex public-key
pins, and nonempty CSR bytes up to 4 KiB. Certificates are nonempty, up to 16 KiB.
Attachment-ID and mounted-ID lists contain unique UUIDv4 values, at most 64; terminal-ID
lists and terminal attachment-ID lists are at most 32. Status mounted/terminal
sets are disjoint. No relation to configured attachments is inferred by wire.

Phases: `configured`, `keys-offered`, `certificates-installed`, `prepare-mounted`,
`prepared`, `prepare-closed`, `runtime-mounted`, `running`, `aborted`, `terminal`.
No transition legality is enforced here.

Codes: `invalid-frame`, `binding-mismatch`, `scope-mismatch`, `configuration`,
`sequence`, `phase`, `certificate`, `mount`, `prepare`, `start`, `aborted`,
`terminal`, `internal`. These are fixed vocabulary, never diagnostic text.

## Process completion and private authority

A completed workload (including nonzero and signal exits) is not a private-channel
failure. The session retains its runtime attachments while the host collects the
ordinary supervisor wait result and final output, retires the exact attachments,
and tears down the VM. Private `phase: running` describes the one-shot session
phase, not a claim that the workload process is still running; ordinary supervisor
status/wait remains the process-status authority. Completion never permits another
start, configuration, key offer or credential installation.

The workload wait worker remains joined by `Serve`, even when `Stop` fails.
Actual channel loss, cancellation and attachment failure still cancel the session,
stop the owned workload and close its attachments. They do not authorize terminal
commands, reconnection, credential reuse or a fabricated drain receipt.

## Configuration hierarchy

Peer is exactly `{tlsRootDER, serverDER, serverKey, dataAddress}`. DER fields are
nonempty public certificate bytes up to 16 KiB each, serverKey is 64 lowercase
hex, and dataAddress is a raw literal IPv4 or IPv6 address: no DNS, brackets,
scheme, port, or zone. The data port is fixed **2049**, not a wire option.

Mount is exactly `{index, volume, destination, subpath, mode, noCopy}`. Index is
uint32 < 64 and unique; volume is a UUIDv4. Destination is absolute. Destination
and subpath are at most 4096 UTF-8 bytes, with no NUL; explicit empty subpath is
valid. noCopy is a required boolean. Paths are not cleaned or normalized here.

Slot is exactly `{volume, attachment, role, mode}`, with UUIDv4 identities.
There are 0...64 mounts and **0...64 total slots**. Attachments and
(volume, role, mode) tuples are unique. Mount and slot volume sets are identical.
Each volume has exactly one prepare/read-write slot. Its runtime slots are
exactly the distinct modes requested by that volume's mounts, with no extras.
Repeated mounts can share one required runtime slot.

## Opaque workload and secret boundary

**CALLER MUST set `Workload.ioClaim` to empty BEFORE serialization**, serialize
once, and retain those exact original bytes through the prepare command.
`SpecificationDigest` is lowercase SHA-256 of precisely those bytes. Prepare
requires nonempty workloadJSON decoded bytes up to **512 KiB**, and the exact
hash must match scope.specificationDigest. The wire codec MUST NOT unmarshal,
normalize, or reserialize opaque workload bytes (even malformed JSON is opaque).
The session and native adapter validate the actual workload shape, exact field
spelling, and empty embedded ioClaim **before injecting the separate secret**.
Digest verification always uses the original bytes, never the decoded object.

The separate ioClaim string may be empty, is at most 4096 UTF-8 bytes, and has no
NUL. PKI DTO fields contain public certificates, CSRs, and key pins only: never
private keys. **ioClaim is secret: never log Frame, Payload, encoded wire JSON,
or workload bytes.** Parser errors contain only `invalid-frame`.

## Mandatory integration obligations (not implemented by the codec)

Wire validity is **not authority**. Pin the binding and complete scope to the
sealed **4105** boot authority before accepting work; comparison with the
self-reported frame alone is insufficient. Use one persistent connection, at
most one command in flight, and strictly increasing nonzero sequences without
wraparound. Bound notification delivery to a **32-entry nonblocking queue**;
the integration owns overflow handling, teardown, authentication, pinning,
certificate verification, phase transitions, attachment membership, and
filesystem/workload validation. This codec creates no sessions or connections.

## Shared conformance corpus

`testdata/vectors.json` contains `{valid: [rawJSONString...], invalid: [rawJSONString...]}`.
Both sides decode the exact raw vector bytes, with no NSNumber/JSON reserialization.
Valid cases cover every command and success/error reply kind; invalid cases
exercise closed shapes, malformed raw JSON, hierarchy, identity, and bounds.
Both Go and Swift consume this same file. Swift entry points are
`WorkloadStorageProtocol.encode(_ frame: Frame) -> Data` (prefixed) and
`decode(from body: Data) -> Frame` (unframed). Swift `frameBodyLength(from: Data)`
validates the four-byte prefix BEFORE body allocation; `readFrame(readExactly:)`
provides a synchronous bounded reader. An async owner can use the prefix helper
before its async body read. Both readers require caller-owned absolute I/O deadlines.
Go entry points are
`WriteFrame(io.Writer, *Frame) error`, `ReadFrame(io.Reader) (*Frame, error)`, and
`Decode([]byte) (*Frame, error)`. Go `Frame.Scope` is `*Scope` (nil only for hello).
Swift `Frame.scope` is `Scope?`. Both expose typed `Payload` optional fields;
`operation` and `kind` select the exact table above, never an arbitrary map.
`NewFrame(operation, binding, scope, data)` constructs a scoped Go frame;
construct hello with `Frame{Version: Version, Type: Type, Operation: "hello", Binding: binding}`.
Swift `Frame(operation:binding:scope:sequence:kind:data:)` defaults version/type,
all optional fields to nil, and data to an empty Payload. `Scope`, `Peer`,
`Slot`, `MountBinding`, `Offer`, and `BootBinding` have public memberwise initializers.
Swift enums are `Operation`, `Kind`, `Role`, `Mode`, `Phase`, `Code` (raw wire strings).
`specificationDigest(Data)` / `SpecificationDigest([]byte)` hashes exact bytes.
 Go additionally checks raw invalid
UTF-8, framing, maximum sizes, short writes, exact hashing, and parser bounds.
