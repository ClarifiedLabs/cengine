import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class GuestBuildScriptTests(unittest.TestCase):
    def test_guest_build_bootstraps_a_checksum_pinned_go_toolchain(self) -> None:
        builder = (ROOT / "Scripts" / "build-guest-assets.sh").read_text()
        toolchain = (ROOT / "Scripts" / "ensure-go-toolchain.sh").read_text()

        self.assertIn('ensure-go-toolchain.sh', builder)
        self.assertIn('VERSION=1.26.5', toolchain)
        self.assertIn('https://go.dev/dl/go$VERSION.darwin-arm64.tar.gz', toolchain)
        self.assertIn('shasum -a 256 -c -', toolchain)
        self.assertIn('efb87ff28af9a188d0536ef5d42e63dd52ba8263cd7344a993cc48dd11dedb6a', toolchain)

    def test_guest_tests_prefer_an_available_host_toolchain(self) -> None:
        script = (ROOT / "Scripts" / "test-guest.sh").read_text()

        self.assertIn('command -v go', script)
        self.assertIn('go env GOOS)" = linux', script)
        self.assertIn("exec go test ./...", script)

    def test_e2fsprogs_build_uses_static_target_with_prerequisites(self) -> None:
        script = (ROOT / "Scripts" / "build-e2fsprogs.sh").read_text()

        self.assertIn('make -j"$(nproc)" libs', script)
        self.assertIn('make -C misc -j"$(nproc)" mke2fs.static', script)
        self.assertIn('install -m 0755 misc/mke2fs.static /mke2fs', script)

    def test_kernel_build_includes_virtiofs_in_the_guest_kernel(self) -> None:
        config = (ROOT / "Configuration" / "cengine-kernel.fragment").read_text()
        builder = (ROOT / "Scripts" / "build-kernel.sh").read_text()

        self.assertIn("CONFIG_FUSE_FS=y", config)
        self.assertIn("CONFIG_VIRTIO_FS=y", config)
        self.assertIn("grep -qx 'CONFIG_VIRTIO_FS=y' /build/.config", builder)


if __name__ == "__main__":
    unittest.main()
