# Raw VM runtime

The runtime uses macOS system frameworks directly. It does not link Apple
Containerization and does not run a shared Linux VM containing Docker.

## Ownership

- The API daemon owns persisted Docker metadata and the native Swift OCI store.
- A dedicated host shim process owns each container `VZVirtualMachine`.
- The infrastructure shim owns the storage appliance VM and VLAN switch.
- The required root networking service owns raw vmnet uplinks and passes packet
  file descriptors to the unprivileged infrastructure shim.
- Shims authenticate local control frames with per-shim 256-bit tokens and keep
  running when the API daemon exits.
- Container create uses a temporary boot to apply OCI layers to its private ext4
  disk. Start boots a fresh guest from that disk and launches the workload as PID
  1 in new PID, mount, IPC, UTS, network, and cgroup namespaces.

## Workload and exec semantics

The workload ext4 filesystem replaces `/` in the workload mount namespace; it is
not merely installed as a chroot beneath an initramfs mount root. This distinction
is required by nested runtimes, which reopen a process root through `/proc` and
expect it to be the namespace root. A read-only root remount therefore applies to
both the init process and later exec processes, while mounts such as tmpfs retain
their own write policy.

Exec uses three guest stages. The first joins the workload UTS, IPC, network, and
cgroup namespaces while retaining access to supervisor resources. It captures
the workload root plus mount and PID namespaces through close-on-exec descriptors
and starts a second stage. The second stage joins the mount namespace, selects
the workload PID namespace, and starts a third stage in a dedicated leaf beneath
the workload cgroup. The third stage enters the captured root, applies the
resolved cwd and configured process rlimits, drops to the requested user and
supplementary groups, applies capabilities and `no_new_privs`, then replaces
itself with the requested command. Keeping rlimits in the final stage prevents
application limits from constraining the guest supervisor or signal/status
proxies. This preserves workload-level resource accounting while allowing
nested runtimes to create their own child cgroups. The first two stage
boundaries proxy catchable signals and preserve child exit status;
uncatchable signals resolve and target the final staged child directly so the
wrappers can reap it and healthcheck targets cannot survive a timeout.
Healthchecks use the same path and resolver.

Omitted exec values resolve in Docker order: explicit exec value, container
override, image configuration, then `/` for the working directory and root for
the user. Environment values merge image, container, then exec entries. When
neither the container nor exec request is privileged, cengine sets
`PR_SET_NO_NEW_PRIVS`; an explicitly privileged exec or an exec inheriting a
privileged container omits it and receives the effective privileged capability
set.

These are observable Docker/OCI semantics, not an OCI runtime-CLI implementation.
The normative coverage and remaining runtime gaps are tracked in
[Docker compatibility](docker-compatibility.md#runtime-semantics-and-oci-applicability).

## CPU and memory

Docker CPU and memory settings are workload hard limits. The guest cgroup uses
the requested memory value unchanged, while the per-container VM capacity adds
5% plus 64 MiB for the guest kernel and cengine supervisor (with a 256 MiB VM
minimum). CPU quota remains the requested whole-CPU count.

Each container shim monitors macOS memory pressure. On the first warning or
critical event in a pressure cycle, it asks the guest to compact memory and
report `MemAvailable`, then inflates the virtio balloon only for availability
above a 512 MiB–1 GiB safety cushion. A normal event restores the VM to its full
capacity and rearms reclamation. Repeated pressure events do not cause repeated
compaction, and paused or unreachable guests fail open. The infrastructure
storage VM is excluded because it uses the infrastructure start path rather
than container guest control.

## Images and disks

OCI manifests, indexes, configs, and blobs live in a content-addressed native
Swift store. Pull, push, tag, remove, history, OCI-layout load/save, digest
verification, platform selection, and reachability pruning do not call an
external engine. The guest applies gzip or zstd layers with whiteouts, xattrs,
devices, deferred hard links, timestamps, and descriptor-safe path traversal.

Each container has a sparse private ext4 root disk. Volumes with a single known
consumer use their own sparse ext4 disk, attached directly to that container's
VM. The storage appliance owns a separate sparse ext4 disk containing volumes
that must be mounted by multiple container VMs. Container root disks default to
64 GiB; block-backed named volumes and the shared storage disk default to 512
GiB. These files are sparse, so their host allocation grows with writes rather
than consuming their logical capacity immediately. macOS never mounts any of
these filesystems.

## Volumes

Volume placement is selected before its first workload start and persisted in
`volume-storage.json`:

- A volume referenced by one known container is block-backed. Its ext4 disk is
  attached to that container VM and mounted by the guest supervisor. This gives
  nested runtimes such as BuildKit and kind the local filesystem semantics
  required by overlayfs.
- A volume referenced by multiple known containers is shared. The storage
  appliance is its sole ext4 owner and exports the volume over NFSv3.

The storage appliance export is reachable only on management VLAN 4094, which
is reserved from Docker networks. Each container supervisor has a deterministic
address in `100.64.0.0/10`, mounts the export once with the Linux kernel NFS
client, and bind-mounts only authorized shared-volume directories into the
workload namespace. The workload never receives the parent trunk interface or
access to the export root. This retains one container per VM while allowing one
storage VM to provide coherent POSIX access to concurrently shared volumes. The
authenticated vsock storage protocol remains limited to administrative
operations such as volume deletion.

The current runtime does not promote an already-used block-backed volume to
shared storage. If a later container introduces a second reference after the
volume's block mode has been persisted, start fails rather than attaching one
writable ext4 disk to two VMs or silently copying potentially live data. Normal
Compose creation works because all container references are known before the
first workload starts.

## Networking

Every VM has one file-handle-backed trunk NIC. The storage VM and every
container supervisor share the isolated management VLAN 4094. A container shim transports
framed Ethernet packets to the infrastructure shim. The switch learns MACs and
forwards only within the VLANs authorized for that shim. cengine-init creates
VLAN devices on the trunk and moves only those devices into the workload network
namespace; the workload cannot access the trunk parent or management VLAN.

Each normal Docker network has a raw vmnet shared-mode uplink configured with
the same IPv4 subnet. The root networking service adds/removes VLAN tags and
supplies NAT, DNS, host access, and published TCP/UDP port rules. Internal
networks use vmnet host-only mode. Isolated networks are switched locally
without any uplink.

## Guest assets

`make guest-assets` produces `.build/guest/` containing:

- `vmlinux`, fetched from the dedicated release in
  `Configuration/kernel-release` or supplied through `CENGINE_LOCAL_KERNEL`;
- `container-initramfs.cpio.gz` with the static `cengine-init` supervisor;
- `storage-initramfs.cpio.gz` with the static storage service;
- a pinned, statically linked arm64 `mke2fs`; and
- `SHA256SUMS` covering the installed boot assets.

Release packaging installs these files under the app's
`Contents/Resources/guest`; standalone CLI distribution uses `share/cengine`.
