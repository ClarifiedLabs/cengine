#!/usr/bin/env python3
from _checks import REPO_ROOT, read, require_absent, require_contains


def main() -> None:
    script = read(REPO_ROOT / "Scripts/package-release.sh")
    entitlements = read(REPO_ROOT / "Configuration/cengine.entitlements")
    info_plist = read(REPO_ROOT / "Configuration/cengine-Info.plist")
    project = read(REPO_ROOT / "cengine.xcodeproj/project.pbxproj")
    build_script = read(REPO_ROOT / "Scripts/build-release.sh")
    makefile = read(REPO_ROOT / "Makefile")
    for needle in (
        'PAYLOAD_ROOT/usr/local/bin', 'dev.cengine.engine.pkg', 'codesign --force',
        '--options runtime', 'productsign --sign', 'notarytool submit',
        'stapler staple', 'spctl --assess --type install', 'verify-entitlements.sh',
        "sed -nE 's/.*MARKETING_VERSION", 'xattr -cr "$PAYLOAD_ROOT"',
        'DMG_PATH="$OUTPUT_DIR/cengine-$VERSION.dmg"', 'hdiutil create',
        'hdiutil verify', 'spctl --assess --type open',
        'install_name_tool -delete_rpath', 'PackageFrameworks',
    ):
        require_contains(script, needle, "package-release.sh")
    require_contains(entitlements, "com.apple.security.virtualization", "cengine.entitlements")
    require_absent(entitlements, "com.apple.developer.networking.vmnet", "cengine.entitlements")
    require_absent(entitlements, "com.apple.vm.networking", "cengine.entitlements")
    for contents, label in ((script, "package-release.sh"), (build_script, "build-release.sh"), (makefile, "Makefile")):
        require_contains(contents, "CENGINE_GIT_COMMIT", label)
        require_contains(contents, "CENGINE_BUILD_TIME", label)
    require_contains(info_plist, "$(CENGINE_GIT_COMMIT)", "cengine-Info.plist")
    require_contains(info_plist, "$(CENGINE_BUILD_TIME)", "cengine-Info.plist")
    require_contains(project, 'INFOPLIST_FILE = "Configuration/cengine-Info.plist"', "project.pbxproj")
    require_contains(project, 'LD_RUNPATH_SEARCH_PATHS = ""', "project.pbxproj")
    if project.count("CREATE_INFOPLIST_SECTION_IN_BINARY = YES") != 2:
        raise AssertionError("cengine Debug and Release builds must embed version metadata")


if __name__ == "__main__":
    main()
