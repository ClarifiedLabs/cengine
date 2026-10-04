# Lifecycle control transport

The package provides two authenticated control transports:

- `NewLifecycleServer` / `NewLifecycleClient` serve the signed lifecycle protocol.
- `NewPKILifecycleWorkloadServer` / `NewPKILifecycleWorkloadClient` serve workload
  protocol v3, bound to the complete lifecycle identity, service epoch, and current
  controller. They accept immutable storagepki credentials, not caller TLS hooks.

Workload admission requires a configured identity policy and rejects successor
identities. Takeover bodies on the workload endpoint are decoded as raw JSON
only to return an explicit refusal; actual takeover belongs to the dedicated
signed lifecycle endpoint.

## Shared contracts

Lifecycle registry snapshots use schema 4. Workload receipts and DATA journals
retain schema 3 contracts. There is no migration path; storage authority recovery
evidence and DATA admission rules remain mandatory.

Connections own raw sockets on success and failure. TLS 1.3 mutual authentication,
exact URI/SPKI policy, bounded frames/connections, strict JSON, ordered calls,
query leases, and no automatic reconnect/replay remain required. Socket loss or
cancellation never releases DATA guards or fabricates retirement completion.
Authenticated idle connections retain their bounded slots without allocating a
request frame; the first decrypted byte starts the absolute request deadline.

Workload regressions use the real lifecycle authority and production v3 TLS
constructors, including retirement barriers, duplicate retries, lost replies,
strict framing, bounded admission, and idle-session deadlines. Lifecycle tests
cover signed takeover, wrong identity/epoch/role, legacy hello/takeover refusal,
malformed responses, service result replay, session admission, and zero-policy
rejection.

## Verification

From `Guest/`:

```sh
go test ./internal/storagecontrol
go test -tags cengine_prepare_full_compat ./internal/storagecontrol
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c ./internal/storagecontrol -o /tmp/storagecontrol-linux-arm64.test
```

Cross-compilation is not Linux filesystem or VM execution.
