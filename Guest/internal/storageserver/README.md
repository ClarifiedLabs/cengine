# Managed storage DATA server

The storage service uses this DATA server with managed ext4 dispatch. The
service owner supplies connections; this package opens no listener or mount.
`storagewire/README.md` owns the exact wire/profile contract, and
`storagemanaged/README.md` describes filesystem and kernel requirements.

## Explicit construction and ownership

1. `New(Config{TLSConfig: config, ClientRoots: rootDER, RequestRetirement: callback})` creates exactly one
   service-global namespace mutex, `storagemanaged.Registry`, and identity Worker.
2. Set `storageauthority.Config.Barrier = server.Barrier` before initializing or
   opening the actual authority. `Barrier` forwards to `Registry.Barrier`; only
   authority may fence admission, join guards, and invoke it.
3. Pass an owned **raw** `net.Conn` to `server.Serve(ctx, authority, raw)`.
   Serve constructs server-side TLS with its private configuration; existing
   `*tls.Conn` wrappers are rejected. Every Serve on this Server must use that same
   Authority. The service opens no sockets and exposes no TLS config getter.

The TLS configuration must explicitly set TLS 1.3 minimum **and maximum**,
`RequireAndVerifyClientCert`, nil `RootCAs` **and** `ClientCAs`, static server certificates,
`SessionTicketsDisabled: true`, no client session cache, dynamic certificate/config
or verification callbacks, external signer, custom entropy/time, key logging,
renegotiation, ECH, or session wrapping/unwrapping. Early data is unsupported. Verified
live TLS state and no resumption are checked, followed by real
`Authority.AuthenticateData` during strict ServerHello / ClientHello / RootReply.
The exact required profile is not negotiated down. Constructor-owned certificate
DER/chains, reparsed leaf certificates, and PKCS#8-roundtripped RSA/ECDSA/Ed25519
private keys retain no caller-owned signing state. `ClientRoots` is the nonempty DER
list that supplies **all** client trust; it is copied and reparsed into a private
pool. Caller CA pools are rejected even when their certificates match the DER:
`x509.CertPool.Equal` ignores `AddCertWithConstraint` callbacks, while `Clone`
shares parsed certificate objects and cannot enumerate certificate DER. Neither
can establish independently owned static trust. Inputs must not be concurrently
mutated during New; later mutations cannot change the server's TLS identity or
roots. Configuration errors return before any server or retirement callback is
created/invoked. A fabricated principal never reaches dispatch.

The DATA API remains distinct from `storagecontrol`: it accepts static
RSA/ECDSA/Ed25519 keys and does not adopt control's single-Ed25519, exact-EKU leaf
policy. Both constructors require nil CA pools and explicit DER trust inputs.
Raw `crypto/tls` clients and the native FUSE fixture's separate controller TLS
handshake still need their normal CA pools; do not remove their chain verification.
The FUSE fixture passes a nil-pool clone only to `storageserver.New`.

The managed constructor obtains `Guard.DupVolumeRoot` itself and transfers every
retained descriptor into registry/barrier ownership before the root guard releases.
No root pathname or caller-supplied root descriptor enters managed dispatch.
Read-only attachment setup uses a verified detached read-only/noatime mount view;
missing required mount/idmap verification fails closed.

## Typed construction after authority generates E

`NewResources` owns the namespace/worker/managed registry before authority opens.
Use `resources.Barrier` in the authority constructor, then consume the resources
exactly once with `NewPKIWithResources(resources, authority, PKIConfig)` after E is
known. The typed path validates server S/E against real StartupMetadata, privately
constructs TLS from immutable PKI values, and checks full attachment URI plus pin
before actual registry authentication. It accepts no TLS config/pool/hook to strip.
`NewWithResources` preserves the original strict generic snapshot policy.

Resource Idle accounting is only for shutdown: successful managed setup is recorded
under its still-held guard and only successful real authority barriers remove it.
Failed setup closes its resources; transport never invents a barrier/drain result.

## Scheduling, limits, and failure

Defaults: 32 connections, 16 shared runtime receive-frame reservations (1 MiB each, plus fixed
codec-copy amplification), 64 output messages / 4 MiB per peer, 10s handshake,
30s incomplete-frame, 10s write deadlines. Idle connections have **no inactivity
expiry** and reserve no payload memory. A fixed four-byte header is read first;
the first byte starts one deadline covering header completion, payload-capacity
wait, and payload receipt. Size is checked before allocation, then the sealed wire
decoder validates the payload. TLS/header memory is bounded by connection count.
Receive reservations cover payload decoding through execution. One reader and FIFO
executor per attachment have one queued RPC plus at most one blocked sender.
After Admit, handoff is infallible and uncancelable, including after socket loss;
receive reservations bound accepted work without discarding accepted mutations.

Every complete validated request passes SequenceTracker then real Admit **before**
execution/namespace/identity queues or descriptor lookup. Enqueued work is never
canceled, replayed, or released on socket failure. Guards remain held through
synchronous managed dispatch and joined identity callbacks/resource transfer, then
release **before** bounded output encoding/queueing. Slow readers cannot hold a
mutation guard. A service dispatch-order mutex serializes FS completion plus
nonblocking output handoff; it is distinct from the managed namespace mutex.

Every admitted RPC rechecks the durable copy fence under dispatch, including work
admitted before Begin. A fenced runtime request retains its guard and receive slot
but parks outside dispatch, then rechecks on wakeup. Each authenticated PREPARE
connection has one reserved receive frame so its owner can Finish even when runtime
requests fill the shared pool. Total receive capacity remains bounded by
`ReceiveFrames + Connections`. Unrelated-volume runtime DATA can progress while
slots remain in the shared pool; the global runtime bound does not guarantee
unrelated progress when that pool is saturated. Owner completion releases parked
work without dropping or replaying it.

One ordered bounded writer per peer interleaves replies and invalidations. Output
limits include the in-flight frame until its write returns; a client receiving that
frame does not synchronize the server's release of its capacity. The origin reply
precedes its mutation events (new node ownership is applied first).
All matching-volume recipients receive ObjectID events in managed sequence order
before any later dispatch result; events carry no session NodeIDs. Ordinary
partial-error mutation events are retained. Sticky managed volume faults stop
admission on every matching attachment, attempt bounded ordered terminal output,
and request exact retirement; malformed/network failures close immediately.
Output overload terminates only the overloaded attachment and requests retirement,
never silently dropping its invalidations while keeping it active.

`RequestRetirement(DataHello, error)` runs once asynchronously per authenticated
failed connection, including EOF and setup failure. It must arrange exact `(S,V,A,E,
role,mode)` control-plane retirement; it does not release guards, reset reconnect
state, or constitute a drain receipt. Serve joins all admitted work and the callback.
A factory that registers resources before a handshake timeout leaves those resources
owned by authority/registry retirement; transport never closes them outside drain.
Connection capacity remains charged through callback completion, so blocked control
callbacks cannot cause unbounded goroutine growth. A callback must eventually return;
transport cannot manufacture a safe deadline for control-plane drain ownership.

## Verification

```sh
cd Guest
go test -race -timeout 60s ./internal/storageserver
go vet ./internal/storageserver
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/storageserver-arm64.test ./internal/storageserver
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/storageserver-amd64.test ./internal/storageserver
# Linux root with required identity capabilities and real ext4:
TMPDIR=/path/on/ext4 go test -race -count=1 ./internal/storageserver
```

Native tests use real certificates, net.Pipe TLS, real authority journal/admission,
and an **unexported test-only** executor replacement. They cover authentication,
profile/sequence rejection, no reconnect, three pipelined admitted mutations across
socket loss, 32 idle peers sharing 16 payload slots, partial header/payload deadlines,
output overload, exact retirement, joined factory-timeout ownership, callback capacity,
cross-session ObjectID ordering, authenticated DATA copy-fence waits before/after
Begin, queued runtime work, owner Finish with the runtime pool full, unrelated-volume
DATA progress with spare runtime capacity, terminal partial-mutation events, and independently
owned TLS keys/chains/roots, constrained-pool handshake rejection, constructor
rejection before input mutation, and safe DER-only TLS acceptance. Linux-only tests use actual managed/identity/ext4
create/write/read/fsync/release/forget and authority Barrier, plus a registered
factory timeout whose drain removes only its session while a sibling remains live.
Cross-compilation is not execution or proof of the complete FUSE profile.
