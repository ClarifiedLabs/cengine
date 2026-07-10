#!/usr/bin/env python3
from _checks import REPO_ROOT, read, require_absent, require_contains


def main() -> None:
    script = read(REPO_ROOT / "Scripts/package-release.sh")
    entitlements = read(REPO_ROOT / "Configuration/cengine.entitlements")
    project = read(REPO_ROOT / "cengine.xcodeproj/project.pbxproj")
    for needle in (
        'PAYLOAD_ROOT/usr/local/bin', 'dev.cengine.engine.pkg', 'codesign --force',
        '--options runtime', 'productsign --sign', 'notarytool submit',
        'stapler staple', 'spctl --assess --type install', 'verify-entitlements.sh',
        "sed -nE 's/.*MARKETING_VERSION", 'xattr -cr "$PAYLOAD_ROOT"',
    ):
        require_contains(script, needle, "package-release.sh")
    require_contains(entitlements, "com.apple.security.virtualization", "cengine.entitlements")
    require_absent(entitlements, "com.apple.developer.networking.vmnet", "cengine.entitlements")
    require_absent(entitlements, "com.apple.vm.networking", "cengine.entitlements")
    if project.count("CREATE_INFOPLIST_SECTION_IN_BINARY = YES") != 2:
        raise AssertionError("cengine Debug and Release builds must embed version metadata")


if __name__ == "__main__":
    main()
