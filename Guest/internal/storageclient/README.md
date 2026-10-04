# Managed storage DATA client

This client is used by the production managed FUSE adapter; it owns no listener
or mount and provides no reconnect. `../storagewire/README.md` and the ABI 3
contract in kernel patch 0002 are authoritative. This package does **not** prove the advertised kernel profile.

## Adapter-facing API

- `New(Config) (*Client, error)` takes exclusive ownership of an already-connected,
  already-handshaken client `*tls.Conn`. Supply exact wire version/profile, expected
  `DataHello` (including epoch and immutable S/V/A/role/mode), server public-key
  fingerprint, supported Linux capability mask, explicit limits and timeout.
- `TLSConfig` must be the actual unchanged client settings used to create Conn:
  TLS 1.3 only, tickets disabled, nil session cache, normal certificate verification,
  one fixed client certificate whose public key matches the attachment binding.
  The observed TLS state must be verified, non-resumed TLS 1.3 with the pinned
  server key and server-auth certificate. Go cannot introspect Conn's original
  settings or prove to the client that the server required mutual TLS; supplying
  the actual settings and server-side verification are transport-owner obligations.
- `Capture(deliveringFD, exactUnique) (Snapshot, error)` performs both ABI-3 ioctl
  queries **synchronously before any FUSE response**. Use the descriptor that read
  this unreplied request, not a cloned peer device, PID, or header UID/GID. The
  adapter must prevent reply/device-close races during both queries. Full groups,
  immutable metadata from the same Unique, exact effective capabilities, and equality of kernel CAP_VALID_MASK to the
  supported mask are checked. Errors never become NONE. The native ioctl is built
  only for Linux arm64/amd64; Darwin and other targets fail closed.
- `Do(snapshot, noneKind, wireBody) (Result, error)` serializes one complete RPC at
  a time in admission order. PRESENT requires `noneKind=0`; captured NONE requires
  explicit `OpenGrantAuth`, `NodeMetadataAuth`, or `LifecycleAuth`, then the frozen
  operation policy and live grant checks apply. A zero snapshot is invalid.
  SETATTR requires captured PRESENT metadata with VALID. `Do` rejects any
  caller-supplied `SetAttrRequest.Semantics` (even matching), then stamps the exact
  immutable captured value before validation/admission. Metadata on another opcode
  or NONE is rejected. No header, PID or older-ABI fallback exists.
- `Root()` returns local node 1 and its pinned wire entry. `Node(local)` and
  `Handle(local)` return value-copy wire tokens for request construction.
  `Result.Node`/`Result.Handle` are newly granted local IDs (or zero); use these as
  FUSE node IDs/FHs. `Result.Reply` retains the full validated wire success/error.
  Linux errno replies are not Go transport errors; the adapter must translate them.
- `Forget(localNode, count)` is the special no-reply callback: local bounded
  bookkeeping only. It cannot be replaced with `Do(ForgetRequest)`. Adjacent
  records batch on the execution worker; every batch receives a wire ack.
  RELEASE/RELEASEDIR go through `Capture` + explicit lifecycle `Do` and retain
  capacity until ack. Double release, count corruption, or failed cleanup is fatal.
- `Invalidate(ctx, Notification)` is a required serial callback on a separate
  bounded worker. It receives the event plus recipient-local object/parent node
  mappings, possibly empty. IDs are never reused. The callback must finish kernel
  notifications before returning, honor cancellation, and not call `Close`.
- On `Terminal()` closure, the owner **must abort this exact mount and request
  retirement**. `Abort(reason)` records an adapter/delivery failure without socket
  I/O or waiting. `Err()` provides the reason. `Close()` joins local workers and
  invalidation callbacks. Neither completion nor release ack is an authority drain
  receipt: remote admitted mutations may still run after transport failure.

## Bounds and failure behavior

Requests have a configured concurrent admitted limit; excess work is rejected
before admission, never canceled afterward. Each admitted request has at most one
bounded wire-sized snapshot and one reply. One reader accepts bounded wire frames;
reply matching checks sequence and operation, events check volume and independent
monotonic sequence. RPC/handshake deadlines, EOF, malformed data, unexpected replies,
callback failure, and event overflow terminate the session. No replay or reconnect.
Idle streams have no RPC deadline; an active RPC uses one absolute deadline, not a
renewable per-event timeout. Credential capture concurrency is also bounded.

Node/handle grants reserve quota **before** sending a potentially granting request.
At node capacity even a lookup that might return an existing node is conservatively
rejected. `Limits.Nodes` bounds both distinct retained nodes and aggregate unacked
lookup grants (including the root pin), so repeated lookups cannot create unbounded
cleanup obligations. Live pins are never LRU-evicted. Each lookup grant reserves a
FORGET cell; only consecutive same-node records coalesce, and batching never moves
a later count before an intervening RPC. Each handle reserves one release cell
independent of the ordinary request budget. A forgotten node remains
until its ack and final handle release. The root's lifetime pin is separate from
counted lookup grants and cannot be consumed by FORGET. Returned snapshots/results
are adapter-owned; the adapter must also bound its request dispatch and retention.

## Local graceful-close outcome policy

`CloseGracefully` still requires native syncfs, normal unmount and the full FUSE
callback join before sealing the DATA client. It joins accepted RPCs, reply
application, captures and invalidations and rejects live handles. It does not
certify remote retirement or durability, clear lookup grants, or replay requests.

A frame already read by the receiver still undergoes strict decoding and stream
validation when graceful stop wins the state lock. Unsolicited/duplicate replies,
wrong-volume or duplicate events, and malformed frames prevent clean completion.
A valid event not admitted before stop does not acquire callback/count ownership
or dispatch into the already-quiesced kernel. The receiver then exits without
reading another packet; idle reads are interrupted by closing the owned transport.
The graceful result is published only after the receiver has joined.

The closed policy in `classifyCompletedOutcome` follows Linux
[getxattr(2)](https://man7.org/linux/man-pages/man2/getxattr.2.html) and
[listxattr(2)](https://man7.org/linux/man-pages/man2/listxattr.2.html):

- LOOKUP/ENOENT remains a completed negative lookup.
- GETXATTR/ENODATA is a completed negative attribute query (the attribute is absent
  or inaccessible). The errno is still delivered unchanged; it never means that
  copy-up or a permission-sensitive operation succeeded.
- GETXATTR/LISTXATTR ERANGE on a nonzero buffer remains unresolved until a validated
  successful nonzero-buffer reply for the same wire node, operation, attribute name
  and complete caller credentials. A size-only query, another caller, ENODATA, or
  another operation cannot clear it. The client never initiates a retry itself.
- Pending probes are bounded by `Limits.Requests`; overflow is a sticky incomplete
  result, without eviction. Ordinary Close/Abort retain unresolved evidence.
- All other completed errors remain sticky, including EIO, EACCES/EPERM, ENOTSUP,
  mutation/namespace errors, failed WRITE/FLUSH/FSYNC, and lifecycle cleanup errors.
  Credential/protocol/transport errors and existing ownership barriers are unchanged.

Supervisor copy-up remains independently authoritative: enumeration followed by
GETXATTR/ENODATA still fails its snapshot; unsupported xattrs and tolerated removal
absence do not widen this client's probe policy. In particular, REMOVEXATTR/ENODATA
is not a read-only query and remains conservative here.

## Adapter responsibilities

The `storagefuse` RawFileSystem adapter translates FUSE structs/architecture flags,
classifies explicit NONE provenance, implements request/reply serialization around
credential capture, delivers local notifications, handles discarded FUSE replies,
and aborts/requests retirement on terminal failure. Kernel mount/init profile
enforcement,
zero TTLs, cache flags, checked close-to-open, mmap/killpriv verification, native
init-user-namespace checks, and Linux real-device ioctl tests belong to that
integration. Client unit tests alone do not establish mounted-FUSE/ext4, VM,
Docker, durability, or authority-drain behavior.

## Checks

From `Guest/`:

```sh
go test -race ./internal/storageclient
go vet ./internal/storageclient
GOOS=linux GOARCH=arm64 go test -c -o /tmp/storageclient-linux-arm64.test ./internal/storageclient
```

Fake ioctl unit tests are separate from real-certificate, mutually verified TLS
1.3 `net.Pipe` transport/state tests. Real patched-kernel ioctl coverage belongs to
an independent Linux fixture; native tests do not substitute for that coverage.

Source layout is fixed at 64 bytes: version 3 at 0, semantics at 40,
cap_effective at 48 and cap_valid at 56; ioctl `0xc040e5f0`. Both queries start
with zero input semantics, including the size-to-data query transition. Outputs
must match exactly, including semantics and the complete (not deduplicated) groups.
Semantics is output-only, mask 1023, and zero on NONE/nonmetadata requests.
