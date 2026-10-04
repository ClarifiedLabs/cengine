# Storage helper tests

Run `bash Tests/CEngineNetworkHelperTests/run.sh` without installing helpers, requesting administrator access, or starting VMs. The isolated Swift package compiles the helper backend, XPC routes, and their support sources.

The helper accepts only the signed engine/controller pair specified by its production, compatibility, or separately compiled qualification profile. Networking messages must come from the engine and pass token validation. Tests verify that unsupported storage operations cannot use the networking routes, even with a valid token, and that the helper advertises the required storage capabilities.

`storage-owner-status` remains read-only and production-engine-only. Root administrative enrollment remains local, flock-serialized, and unavailable to XPC callers. No tests install helpers, enroll production owners, or open or modify production storage.

Coverage includes checkpoints, lifecycle operations, production routing, qualification filesystem policy, process generations, descriptors, and ACLs. Persisted bindings use `StorageLifecycleStoreBinding`. Unsupported registration envelopes and authority formats are rejected without changing the stored bytes.

Immediate journal close/reopen tests run in isolated Swift Testing exit-test processes. Concurrent Darwin process launches can transiently retain another test's close-on-exec file descriptions; isolation keeps those tests about journal ownership and corruption, not unrelated spawn timing. Production uses a nonblocking exclusive lock.

Cold recovery coverage includes a completed predecessor adoption and the shared lifecycle/adoption process-metadata bounds. It checks the bounded dead-history/fresh-successor peak, the completion-size delta, and history retirement at L3. Limits are 96 KiB per store with a 16-KiB completion reservation, 128 stores, and 32 MiB aggregate.

These tests do not verify an installed signed engine/helper pair or VM behavior. Native anonymous-XPC tests use real message trailers where applicable, but do not verify a production installation. See [production lifecycle checkpoints](../../docs/storage-production-checkpoints.md).
