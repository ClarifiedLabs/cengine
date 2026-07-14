#!/usr/bin/env python3
from _checks import REPO_ROOT, read, require_absent, require_contains


def main() -> None:
    test = read(REPO_ROOT / ".github/workflows/test.yml")
    release = read(REPO_ROOT / ".github/workflows/release.yml")
    makefile = read(REPO_ROOT / "Makefile")
    engine_entitlements = read(REPO_ROOT / "Configuration/cengine.entitlements")
    for needle in ("- main", "- release-ci", "pull_request:", "workflow_dispatch:", "runs-on: macos-26", "make test"):
        require_contains(test, needle, "test.yml")
    for needle in (
        "- release-ci", "v*.*.*", "require-tests:", "guest-assets:",
        "runs-on: ubuntu-24.04-arm", "DOCKER_CONTEXT: default",
        "docker --context default buildx version",
        "needs: [require-tests, guest-assets]",
        "CENGINE_SIGN_RELEASE=1", "CENGINE_NOTARIZE=1", "./Scripts/package-release.sh",
        "gh release create", "homebrew-publish:", "ClarifiedLabs/homebrew-tap",
        "Upload release artifacts", ".pkg", "PKG_SHA256",
        "Verify Homebrew Cask installation",
        "--check-notarization", "com.apple.security.virtualization",
    ):
        require_contains(release, needle, "release.yml")
    for forbidden in ("draft: true", "--draft", "TestFlight"):
        require_absent(release, forbidden, "release.yml")
    require_contains(engine_entitlements, "com.apple.security.virtualization", "cengine.entitlements")
    require_absent(release, "com.apple.vm.networking", "release.yml")
    require_absent(engine_entitlements, "com.apple.vm.networking", "cengine.entitlements")
    if (REPO_ROOT / "Configuration/cengine-network-helper.entitlements").exists():
        raise AssertionError("the root network helper must not claim restricted vmnet entitlements")
    for forbidden in (
        "brew install docker",
        "install-compose-compat.sh",
        "make test-compat",
        "system install",
    ):
        require_absent(test, forbidden, "test.yml")
    require_contains(
        makefile,
        'CENGINE_BINARY="$(XCODE_DERIVED_DATA)/Build/Products/Debug/cengine"',
        "Makefile",
    )
    for target in ("test-compat", "test-compat-soak", "test-compat-oracle"):
        require_contains(makefile, f"{target}:", "Makefile")
    if makefile.count("$(CENGINE_COMPAT_ENV)") != 3:
        raise AssertionError("all compatibility test targets must pass isolated runtime assets")
    guest_builder = read(REPO_ROOT / "Scripts/build-guest-assets.sh")
    require_absent(guest_builder, "docker buildx build", "build-guest-assets.sh")
    for needle in ("CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "-buildvcs=false"):
        require_contains(guest_builder, needle, "build-guest-assets.sh")
    compat_sign = read(REPO_ROOT / "Scripts/sign-compat-binary.sh")
    for needle in (
        "/Applications/cengine.app/Contents/MacOS/cengine-network-helper",
        "dev.cengine.engine",
        "Configuration/cengine.entitlements",
        "security find-identity -v -p codesigning",
        "PackageFrameworks",
        "-name '*.framework'",
        "-name '*.dylib'",
    ):
        require_contains(compat_sign, needle, "sign-compat-binary.sh")


if __name__ == "__main__":
    main()
