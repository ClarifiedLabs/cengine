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

The storage appliance exports its ext4 volume directory over NFSv3 on VLAN
4094, which is reserved from Docker networks. Each container supervisor has a
deterministic address in `100.64.0.0/10`, mounts that export once with the Linux
kernel NFS client, and bind-mounts only authorized named-volume directories into
the workload namespace. The workload never receives the parent trunk interface
or access to the export root. This presents standard `nfs` mount metadata to
Linux tools such as cAdvisor while retaining one container per VM and one ext4
owner for concurrently shared volumes. The authenticated vsock storage protocol
remains limited to administrative operations such as volume deletion.

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

- `vmlinux`, built from the exact commit recorded by `Scripts/build-kernel.sh`;
- `container-initramfs.cpio.gz` with the static `cengine-init` supervisor;
- `storage-initramfs.cpio.gz` with the static storage service;
- a pinned, statically linked arm64 `mke2fs`; and
- `SHA256SUMS` covering the installed boot assets.

Release packaging installs these files under the app's
`Contents/Resources/guest`; standalone CLI distribution uses `share/cengine`.
