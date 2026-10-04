# Raw VM runtime

cengine uses macOS system frameworks directly: one workload container per
Virtualization.framework VM, not Docker Engine inside a shared Linux VM.

## Ownership

- The API daemon owns persisted Docker metadata and the native Swift OCI store.
- A dedicated host shim owns each container `VZVirtualMachine`.
- The infrastructure shim owns the storage appliance VM and VLAN switch.
- The privileged helper owns raw vmnet uplinks and passes packet descriptors to
  the unprivileged infrastructure shim. It also owns protected storage lifecycle
  authority; production storage enrollment requires explicit administrator approval.
- Shims authenticate local control frames and survive daemon exit. A replacement
  daemon adopts exact owned live VMs rather than restarting their containers.
- Create uses a temporary boot to apply OCI layers to a private ext4 disk. Start
  boots that disk and launches workload PID 1 in private PID, mount, IPC, UTS,
  network and cgroup namespaces.

Shim sockets use a randomly named, owner-only boot-session directory under `/tmp`
to fit Darwin's Unix socket path limit. Its boot UUID, canonical path, owner UID,
filesystem UUID and inode are recorded durably. Same-boot replacements reopen only
that identity; a new boot records a new directory without deleting a path that may
belong to another process.

Cleanup uses the persisted generation journal. Same-boot identity mismatch fails
closed. A generation proven to predate the current boot may retire stale publication
only after confirming that none of its recorded artifact, staging or claim names
exist in the replacement directory; it never modifies the replacement directory.

## Workload and exec semantics

The workload ext4 filesystem replaces `/` in its mount namespace rather than
remaining a chroot beneath the initramfs. Nested runtimes reopening `/proc` process
roots therefore see the namespace root. Read-only-root policy applies to both init
and exec, while explicit mounts retain their own policies. tmpfs defaults to writable
`noexec,nosuid,nodev`; structured `exec`/`noexec` changes its execution flag.

Mounts are depth-ordered so parents cannot hide submitted children. Read-only named
volumes use recursive mount attributes; later writable children retain their policy
on both direct ext4 and managed shared FUSE volumes.

Exec has three stages: join workload namespaces while retaining supervisor access;
join the captured mount namespace and select the PID namespace; then enter the
captured root in a dedicated cgroup leaf and execute the command. Close-on-exec
namespace/root descriptors preserve exact identity. The final stage applies cwd,
rlimits, selected seccomp, user/groups, capabilities and `no_new_privs`. Applying
rlimits there avoids constraining the supervisor and signal/status proxies.
Catchable signals and exit status pass through the staging processes; uncatchable
signals target the resolved final child so wrappers can reap it. Healthchecks use
the same resolver and execution path.

Omitted exec values resolve from explicit exec input, container override, image
configuration, then `/` and root defaults. Environment merges image, container and
exec entries. The container's explicit no-new-privileges policy applies to init,
exec and healthchecks, defaulting to false; privilege does not silently select it.
Seccomp is independent: unprivileged containers default to the built-in arm64
profile, privileged containers are unconfined unless explicitly selecting built-in,
and `seccomp=unconfined` disables filtering. Custom profiles and cross-VM namespace
sharing are explicit gaps in [Docker compatibility](docker-compatibility.md#runtime-semantics-and-oci-applicability).
These are Docker/OCI execution semantics, not a public OCI runtime CLI.

## CPU and memory

Docker CPU and memory settings are workload hard limits. VM capacity adds 5% plus
64 MiB to workload memory, with a 256-MiB VM minimum, for the kernel and supervisor.
CPU quota remains the requested whole-CPU count.

On the first warning/critical event in a macOS memory-pressure cycle, each container
shim asks its guest to compact memory and report `MemAvailable`, then inflates its
virtio balloon only above a 512-MiB–1-GiB safety cushion. Normal pressure restores
full capacity and rearms reclamation. Repeated warnings do not repeat compaction;
paused/unreachable guests fail open. The storage VM does not use this path.

## Images and disks

OCI indexes, manifests, configs and blobs live in a content-addressed Swift store.
Pull/push, tagging, history, OCI-layout load/save, digest verification, platform
selection and reachability pruning do not invoke another engine. Guest extraction
supports gzip/zstd layers, whiteouts, xattrs, devices, deferred hardlinks, timestamps
and descriptor-safe traversal. Linux amd64 execution uses Rosetta for Linux when
installed; arm64 is the default.

Each container has a sparse private ext4 root disk, defaulting to 64 GiB. Direct
named-volume disks and the shared storage disk default to 512 GiB. Host allocation
grows with writes rather than consuming the logical capacity immediately. macOS
does not mount these filesystems.

## Volumes

Placement is chosen before first workload start and persisted in `volume-storage.json`:

- **One known consumer:** a dedicated sparse ext4 disk is attached directly to that
  VM and mounted by its supervisor. This supplies local filesystem semantics for
  nested runtimes such as BuildKit and kind.
- **Multiple known consumers:** the storage appliance is the sole ext4 owner;
  authenticated per-attachment FUSE clients expose authorized volume roots to the
  workload VMs.

Shared DATA uses mutually authenticated TLS over the isolated management network.
Workloads receive neither storage control credentials nor the global store root.
Private guest/host channels register and retire attachments; every DATA request is
admitted against exact volume, attachment, role, mode and service generation.
See [Generation-fenced drain](storage-generation-drain.md) for authority and PREPARE
semantics, and [Lifecycle checkpoints](storage-production-checkpoints.md) for
adoption, cold recovery and fail-closed uncertainty.

Used block-backed volumes are not promoted to shared storage when a second
reference appears. Start fails rather than attaching writable ext4 to two VMs or
copying live data silently. Compose works when all references are created before
first start. Shared locks are client-local; distributed locking and cross-VM
concurrent mmap coherence are not implied. Unsupported store formats are rejected
without modifying their data; cengine does not migrate or automatically reset them.

## Networking

Each VM has one file-handle-backed trunk NIC. Supervisors and the storage appliance
share reserved management VLAN 4094. Container shims transport framed Ethernet to
the infrastructure switch, which forwards only within each shim's authorized VLANs.
Guest init moves workload VLAN devices into its network namespace; the workload
cannot access the trunk parent or management VLAN.

Normal Docker networks use raw vmnet shared-mode uplinks with matching IPv4 subnets.
The privileged service adds/removes VLAN tags and provides NAT, DNS, host access
and published TCP/UDP rules. Internal networks use vmnet host-only mode; isolated
networks switch locally without an uplink. Unsupported topology and namespace
requests fail explicitly rather than being approximated silently.

## Guest assets

Paired assets include the kernel, container/storage initramfs images, pinned arm64
`mke2fs`, checksums and provenance. Release packages place them in app
`Contents/Resources/guest` or standalone `share/cengine`. The required managed FUSE
kernel ABI must match the guests; a checksum alone is not provenance.

Local assets support development and signed local builds. Canonical publication
is a separate release requirement. See [Development](development.md) for asset
commands, [Release](release.md) for distribution gates and
[Managed storage](storage-adoption.md) for production setup and recovery limits.
