# Native nonexporting lifecycle storage controller

This package contains the native storage controller. It authenticates ROOT
commands and serves the parent over an inherited private channel.

## Boundaries

- `RunLifecycleChild` is the sole controller entry in every `darwin && cgo`
  build. Qualification namespaces and privileges remain separately gated.
- The child accepts only inherited AF_UNIX stream FD 3. Native code validates
  actual parent/child unique IDs and audit tokens; parent DTOs cannot supply them.
  Launchers must retain CLOEXEC_DEFAULT, empty environment, and private bootstrap
  provenance. No listener, caller-selected endpoint, or key import/export exists.
- The sole C/libxpc bridge authenticates immutable ROOT Mach trailers, strict
  Apple signing identity/team, hardened runtime, forbidden entitlements, and
  stable process identity. Production and compatibility namespaces remain closed
  compile-time choices. Qualification separately requires sealed source/asset
  pins; it has no environment or anonymous endpoint bypass.
- The child owns its opaque controller key. ROOT candidate/result/identity/service
  challenges cannot be relayed through the parent operation union. Signed grants
  are independently verified; boot credentials do not establish ROOT boot trust.
- Canonical JSON preserves uint64 exactly and rejects duplicate/unknown fields.
  Four-byte length framing bounds ordinary requests/replies to 64 KiB. Workload
  requests have a separate 256 KiB bound and responses a 4 MiB data bound.
  SCM_RIGHTS is accepted exactly once for `connect-boot`, `stage-service-rebind`,
  `connect-workload`, and `attachment-certificate`; rejected rights are closed.
- Attachment certification checks the exact registered binding and CSR key using
  the current ROOT-authorized lifecycle owner and frozen TLS trust. EOF is
  unavailable, not authenticated denial. Truncated transport and trust failures
  remain fatal.
- Workload loss never authorizes lifecycle reconnect or parent-supplied receipts.
  Clean response-boundary EOF has the existing narrow recovery signal; reset and
  broken-pipe failures fence the service workload lane until committed replacement.

## Verification

From `Guest/`:

```sh
go test ./internal/storagebootstrap
go test -tags cengine_prepare_full_compat ./internal/storagebootstrap
go test -tags cengine_lifecycle_v2_qualification,cengine_prepare_full_compat ./internal/storagebootstrap
```

Native tests exercise production/compatibility policy rejection and process/FD
checks without VM, elevation, or installed ROOT. They do not certify signed,
installed separate-parent/child authorization or private VZ boot provenance.
