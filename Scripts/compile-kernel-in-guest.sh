#!/bin/sh
set -eu

jobs=${1:-auto}
if [ "$jobs" = auto ]; then
    jobs=$(getconf _NPROCESSORS_ONLN)
fi
case "$jobs" in
    ''|*[!0-9]*|0)
        echo "kernel build job count must be a positive integer or auto" >&2
        exit 2
        ;;
esac
export DEBIAN_FRONTEND=noninteractive

apt-get -o APT::Sandbox::User=root update
apt-get -o APT::Sandbox::User=root install -y --no-install-recommends \
    bc bison build-essential ca-certificates flex libelf-dev libssl-dev
rm -rf /var/lib/apt/lists/*

rm -rf /build
mkdir -p /build
make -C /linux O=/build ARCH=arm64 defconfig
/linux/scripts/kconfig/merge_config.sh -m -O /build /build/.config /fragment
make -C /linux O=/build ARCH=arm64 olddefconfig
grep -qx 'CONFIG_FUSE_FS=y' /build/.config
grep -qx 'CONFIG_VIRTIO_FS=y' /build/.config
grep -qx 'CONFIG_NFS_FS=y' /build/.config
grep -qx 'CONFIG_NFS_V3=y' /build/.config
make -C /linux O=/build ARCH=arm64 -j"$jobs" Image
cp /build/arch/arm64/boot/Image /output/vmlinux.next
