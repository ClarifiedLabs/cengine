# storagepki — in-memory lifecycle credentials

The lifecycle controller, private guest bootstrap and managed service use this package. It uses only the Go standard library. It creates no files, keystore, listener, process, environment variable, or command-line interface.

## Trust boundary

* The privileged helper exclusively owns the **separate root-bootstrap TAKEOVER signing key**. This package NEVER generates, accepts, imports, exports, or signs with that private key. `BootstrapPublicKey` accepts only its public value, copied on input/output. ROOT-signed grants are verified separately from TLS issuance.
* `NewIssuer` creates a fresh **TLS-only Ed25519 CA**, with a maximum 24-hour lifetime and path length zero. It cannot export its private CA key. It issues only constrained, non-CA leaves. Bootstrap-root and TLS-CA public keys cannot be issued as leaves.
* Server, controller and each attachment obtain separately generated Ed25519 keys. `NewAttachmentKey` runs in **trusted guest init once per attachment**; only CSR/public material goes to the host bridge. The guest retains the key and combines the returned certificate using `Certificate.WithKey`.
* A controller certificate is **NOT controller authority**. Independently obtain its epoch/key from helper bootstrap grants and the durable authority registry. Verify the TLS scope first, then call the authority's authentication/admission operations against immutable TLS SPKI fingerprints. Recheck registry fencing/admission per request. Certificate renewal with the same role key does not authorize a new epoch; `IssueController` validates the independently supplied exact binding but does not allocate or attest epochs.
* This stateless issuer cannot prove that a public key has **never** been reused across roles, attachments, imports, or former issuers. Constructors mint fresh random keys and `Key.CSR` rejects role changes, but malicious external CSR callers can reuse keys. The authority's durable key/epoch registry must reject historical/cross-role reuse; TLS SAN metadata is not a substitute. There is no misleading global reuse registry here.

## Typed canonical bindings

All IDs are semantic named types. UUID values must be lowercase canonical UUIDv4 (matching `storageauthority.ID`); container IDs are exactly 64 lowercase hex characters. `ControllerEpoch` is a nonzero uint64, not a service UUID. Constructors validate and freeze a value-copy `Binding`:

* Server: `spiffe://cengine.storage/store/<S>/server/<E>`
* Controller: `spiffe://cengine.storage/store/<S>/controller/<decimal-controller-epoch>`
* Attachment: `spiffe://cengine.storage/store/<S>/attachment/<A>/service/<E>/volume/<V>/role/<prepare|runtime>/mode/<read-only|read-write>/container/<container>/launch/<launch>/prepare/<P|->`

Prepare role requires UUID `P`; runtime role requires empty `Prepare`, represented by `-`. Every attachment tuple field participates in the URI. Server leaves have exactly DNS SAN `storage.cengine.invalid` plus the one URI; client leaves have only the one URI. Canonical SAN DER is compared exactly: additional identities, alternative encodings, query/fragment/escaping tricks, DNS names, or unknown GeneralNames are not accepted. Server EKU is exactly serverAuth; controller/attachment EKU is exactly clientAuth. `anyExtendedKeyUsage`, absent/multiple EKUs and CA leaves fail verification.

## Exported API and private-channel flow

* Values: `StoreID`, `ServiceEpoch`, `ControllerEpoch`, `AttachmentID`, `VolumeID`, `LaunchID`, `PrepareID`, `ContainerID`, `Role`, `Mode`, `AttachmentTuple`, frozen `Binding`, `Fingerprint`, `BootstrapPublicKey`, `Key`, `Root`, `Issuer`, `Certificate`, `Identity`.
* Constructors: `NewUUID`, `NewBootstrapPublicKey`, `NewServerBinding`, `NewControllerBinding`, `NewAttachmentBinding`, `NewServerKey`, `NewControllerKey`, `NewAttachmentKey`, `NewIssuer(now, lifetime, bootstrapPublic)`.
* Public-only bridge request: `Key.CSR(expectedBinding)` returns DER PKCS#10. `Key.PublicKey`, `Key.Fingerprint`, `PublicKeyFingerprint` return copied public values. `Fingerprint.String()` is lowercase SHA-256(SPKI DER) hex compatible with `storageauthority.PublicKeyFingerprint`.
* Bridge issuance: `Issuer.IssueServer`, `Issuer.IssueController`, `Issuer.IssueAttachment` each take CSR DER, the **independently expected** validated binding, explicit `now`, and lifetime. They verify the Ed25519 CSR signature and exact SAN, reject other attributes/extensions/subjects, and never copy requested CA privileges. `Issuer.Root()` returns a public TLS root value.
* Guest assembly: `ParseCertificateDER/ParseCertificatePEM` imports the bridge's **public-only** certificate response with the expected binding; `Certificate.WithKey` combines it with the guest's locally retained key and checks exact binding/profile and key match. No attachment private-key export to the bridge is needed. `Certificate.DER/PEM/Binding`, `Root.DER/PEM`, `Binding.URI/Role`, `Identity.Certificate` are public value accessors.
* Private init transport (server/attachment only; controller export is rejected): `Identity.ExportDER/ExportPEM` returns **separate single certificate and PKCS#8 private-key buffers**; `ParseIdentityDER/ParseIdentityPEM` checks size, expected binding, Ed25519 type and key match. `ParseRootDER/ParseRootPEM` imports one self-signed TLS CA. PEM input is exactly the package's canonical PEM output (LF, final newline), with no leading/trailing bytes, headers, duplicate/unknown blocks, or chains. Limits are `MaxDERSize` (16 KiB each) and `MaxPEMSize` (32 KiB each). Parsing is structural, not proof of current trust: TLS still checks roots and real time.
* TLS: `ServerTLSConfig(identity, clientRoot)` returns a fresh **static, callback-free** TLS 1.3 mutual-auth config, suitable for `storageserver`'s allowlisted snapshot policy. After handshake the caller MUST use `VerifyController` or `VerifyAttachment` with independently expected binding and SPKI, before authority admission. Both roles use clientAuth, so ordinary TLS cannot distinguish them.
* `ClientTLSConfig(identity, serverRoot, expectedServerBinding, serverSPKI)` is **attachment-only**; it rejects controller identities rather than exposing their private key in a config. `NewControllerTLSClient(raw, identity, serverRoot, expectedServerBinding, serverSPKI)` returns only a `*tls.Conn`, keeping controller config/key/signers private to this package. It accepts only raw, non-TLS transports; the caller performs the handshake and closes the connection (and retains raw on construction failure). Both factories retain normal chain/EKU/hostname/time verification and add an internal immutable expected-binding/SPKI verifier. `VerifyServer`, `VerifyController`, `VerifyAttachment` require an actual completed, non-resumed TLS 1.3 `ConnectionState`, verified chains, exact leaf scope and pin; they reverify against the supplied root and real current time. Never feed fabricated connection state or derive expected metadata from the peer certificate.

Configs, keys and byte exports do not share mutable storage. Each TLS factory constructs newly parsed certificates, cloned Ed25519 bytes and a new trust pool, **not a shallow `tls.Config.Clone` of caller-owned state**. Treat a returned config as transferred to its connection/server and do not mutate it after use. No external `crypto.Signer` or dynamic callback API is accepted. Server config contains no callbacks; only the client has the package-owned pin/scope callback. TLS session tickets/cache/resumption are disabled, TLS 1.3 is both minimum and maximum. There is no configurable TLS clock: issuance takes explicit time, while real TLS checks the real current clock. Validity is at least one second and at most 24 hours, cannot exceed CA validity, and rejects year-zero starts. Rotation and distribution belong to the lifecycle owners.

Private-key serialization is deliberate only through the explicit transport API. Never put returned bytes in logs, JSON messages on ordinary channels, environment variables or argv. Credential values redact common fmt output and expose no JSON fields. Go heap copies, reflection, caller logging of explicit export buffers, and private-key zeroization are **not** security guarantees provided here.

## Typed lifecycle controller possession proofs

`LifecycleChildGreeting`, `LifecycleChildChallenge` and `LifecycleChildReply`
carry the closed `storage-child-lifecycle.v2` protocol. Canonical decoding
preserves exact uint64 values and rejects noncanonical or unknown fields.
`Key.SignLifecycleChildReply` and `Key.SignLifecycleChildServiceReply` sign only
the validated challenge and matching receipt/result with the opaque controller
key; they do not expose a general signer or the helper's ROOT private key.
`SignLifecycleChildIdentityReply` supplies the separate identity-only proof.

The native transport must authenticate ROOT and independently match daemon/child
audit tokens and unique IDs, incarnation, store, controller key, grant, nonce,
counter, purpose and expiry. A decoded challenge or parent-forwarded receipt is
not authority. See `lifecycle_child.go`, `lifecycle_child_identity.go` and
`lifecycle_service.go` for the exact bounded DTOs, domains and verification rules.

## Verification

From `Guest`:

```sh
go test ./internal/storagepki
go test -race ./internal/storagepki
go vet ./internal/storagepki
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/storagepki-linux.test ./internal/storagepki
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/storagepki-darwin.test ./internal/storagepki
```

Tests perform actual native `crypto/tls` handshakes over `net.Pipe` with correctly timed leaves. They cover fresh role keys, canonical typed bindings, CSR signature/type/scope validation, issuance bounds, strict transports, wrong EKU/SPKI/store/epoch/tuple, expiration, CA leaves, TLS version/no-resumption, and concurrent mutation of independently returned configs. These tests are not installed ROOT, VM, or mounted-filesystem qualification.
