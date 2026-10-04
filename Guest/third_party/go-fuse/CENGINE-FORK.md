# CEngine controlled go-fuse fork

Source copied in full from `github.com/hanwen/go-fuse/v2 v2.11.0`:
`h1:CGVkJh9gRz0pTRMADNcqdFl3ec/5QbE/Vx1Gl7ESozM=`.
The upstream LICENSE and all copyright notices are retained. This is **not** an
unmodified upstream release. Guest/go.mod replaces that pin with this directory;
regenerate Guest/vendor with `go mod vendor` from Guest, never patch vendor alone.

Minimal downstream patch list (all opt-in; nil/default options retain upstream behavior):

1. `MountOptions.ValidateInit`: validate a value-copy of the exact negotiated
   InitOut before serialization; error/panic sends EINVAL, not INIT success.
   Native NewServer fails and closes its owned device after sending rejection.
   Managed INIT errors propagate even when the required validator is missing;
   neither missing hook can produce construction success or call filesystem Init.
2. `MountOptions.ObserveReply` / `ReplyDelivery`: synchronous value-only native
   reply delivery observation before request reuse. Includes exact Unique/opcode,
   result errno, actual/expected byte counts, syscall/short-write errors, canceled
   and suppressed requests. Forces non-splice writes for complete count checking;
   no retry, injected response, or asynchronous response API. Callback must not
   block or call server methods that wait for the current request. ProtocolServer
   cannot claim device delivery and does not call this hook. Managed notification
   writes also check short-write counts.
3. `ManagedProtocol`: Linux-only opt-in protocol 7.33 (upstream defaults to 7.28),
   retained as the fixed managed layout ceiling; ABI3 adapters forbid both
   HANDLE_KILLPRIV versions and atomic O_TRUNC via DisabledCapabilities. Requires both hooks and clears INIT_EXT/flags2,
   which belong to 7.36. Does not pretend all newer request ABIs are implemented.
   Disables the library's internal poll-hack namespace shortcut so managed raw
   callbacks are not bypassed. Non-Linux is rejected.
4. `fuse/managed_hooks_test.go` and `fuse/managed_native_test.go`: deterministic
   INIT/copy/rejection and delivery/short-write/error tests, including native
   Server.handleInit/read/handleRequest against a temporary-file sink, missing
   managed hooks, exact EINVAL delivery, and zero filesystem Init callbacks. No mount, FUSE device,
   privileges or VM needed.

The adapter config must enforce the narrow managed profile and abort/retire on
failed, interrupted, or unexpectedly suppressed delivery. Hooks do not prove
kernel credential ABI 3, checked reopen, mmap, killpriv, or authority drain.
