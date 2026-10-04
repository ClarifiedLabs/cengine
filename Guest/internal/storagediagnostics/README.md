# Temporary, compile-time storage stall diagnostics

Only Linux `cengine-init` and `cengine-storage` built with the
`cengine_storage_diagnostics` Go tag import this sampler. Their tagged `init`
hooks call `Start` only at PID 1, never in stage children. Normal binaries do not
include the sampler. No build script changes are needed or supplied.

The sampler reads **only its own Go runtime** using `runtime.GoroutineProfile`
and `runtime.CallersFrames`. It writes static import-qualified function symbols
and fixed framing/cap markers to the existing private VM console (`os.Stderr`).
Import paths are part of static symbols, not inspected filesystem paths. It does
not emit goroutine IDs, PCs/addresses, arguments, frame source paths/line numbers,
errors, payloads, filesystem state, or keys. It does not use `runtime.Stack` or
pprof, and adds no environment/argument/kernel/syscall/API control surface.

Fixed limits:

- One dedicated goroutine, started once; a boot-time baseline then one sample
  every 5 seconds, **at most 12 snapshots** (nominally 0–55 seconds).
- A separate **60-second deadline from the PID-1 init hook**, not kernel uptime.
  Slow scheduling/output may yield fewer snapshots; no catch-up loop is used.
- **256 goroutine records**, **32 frames per record** (including inline frames).
  If the runtime reports more records than fit, the sample emits only a record
  cap marker, not a partial profile or dynamically enlarged allocation. A full
  32-PC record is conservatively marked capped.
- **128 KiB total output for the entire session**, including markers. A complete
  `capped: output bytes` line is reserved; symbols/lines are never byte-truncated
  by the budget. Caller-owned storage is a fixed 256-record array and a bounded
  128-KiB output buffer; runtime profiling/symbolization has internal overhead.
- Writes are best effort, with no retry, extra logger, or growing queue. An error
  or short write ends sampling. A blocked console can retain the sampler's one
  goroutine; it is not forcibly interrupted or reconfigured. The deadline bounds
  scheduling, not an already-running runtime profile or console write. External
  I/O failure can of course interrupt a line already submitted to the console.

Profiling has nonzero runtime synchronization/allocation overhead and is not a
zero-perturbation probe. Go's preexisting `GODEBUG=profstackdepth` runtime setting
can affect symbol availability and internal scratch allocations (zero depth can
produce no frames). This sampler neither reads nor changes the environment;
its output and caller-owned buffer limits remain fixed. This intentionally
captures no goroutine states, wait
reasons, IDs, or cross-process data. It cannot diagnose non-Go stacks directly.
The untagged internal package is testable on the development host, but only the
tagged command files import it into guest executables. No VM, helper, Docker,
privileged operation, kernel changes, or production storage/transport changes
are part of this sampler.
