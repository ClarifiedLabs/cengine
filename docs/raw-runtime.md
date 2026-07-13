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

## Images and disks

OCI manifests, indexes, configs, and blobs live in a content-addressed native
Swift store. Pull, push, tag, remove, history, OCI-layout load/save, digest
verification, platform selection, and reachability pruning do not call an
external engine. The guest applies gzip or zstd layers with whiteouts, xattrs,
devices, deferred hard links, timestamps, and descriptor-safe path traversal.

Each container has a sparse private ext4 disk. The storage appliance owns a
separate sparse ext4 disk containing named volumes. macOS never mounts either
filesystem.

## Volumes

Container guests mount named volumes through cenginefs, a FUSE-over-vsock
protocol proxied between the container and storage shims. Protocol objects are
connection-scoped inode and open-handle IDs, not host paths. The server uses
`openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)`, parent directory descriptors,
and `*at` syscalls. It supports hard links, rename, xattrs, locks, allocation,
statfs, device nodes, direct I/O, fsync, and cross-client invalidation. Volume
tokens are HMACs derived from a persistent infrastructure secret.

## Networking

Every VM has one file-handle-backed trunk NIC. A container shim transports
framed Ethernet packets to the infrastructure shim. The switch learns MACs and
forwards only within the VLANs authorized for that shim. cengine-init creates
VLAN devices on the trunk and moves only those devices into the workload network
namespace; the workload cannot access the trunk parent.

Each normal Docker network has a raw vmnet shared-mode uplink configured with
the same IPv4 subnet. The root networking service adds/removes VLAN tags and
supplies NAT, DNS, host access, and published TCP/UDP port rules. Internal
networks use vmnet host-only mode. Isolated networks are switched locally
without any uplink.

## Guest assets

`make guest-assets` produces `.build/guest/` containing:

- `vmlinux`, built from the exact commit recorded by `Scripts/build-kernel.sh`;
- `container-initramfs.cpio.gz` with the static `cengine-init` supervisor;
- `storage-initramfs.cpio.gz` with the static storage service;
- a pinned, statically linked arm64 `mke2fs`; and
- `SHA256SUMS` covering the installed boot assets.

Release packaging installs these files under the app's
`Contents/Resources/guest`; standalone CLI distribution uses `share/cengine`.
