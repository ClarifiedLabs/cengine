#!/usr/bin/env python3
import plistlib

from _checks import REPO_ROOT, read, require_absent, require_contains


def main() -> None:
    script = read(REPO_ROOT / "Scripts/package-release.sh")
    entitlements = read(REPO_ROOT / "Configuration/cengine.entitlements")
    app_entitlements = read(REPO_ROOT / "Configuration/cengine-app.entitlements")
    info_plist = read(REPO_ROOT / "Configuration/cengine-Info.plist")
    project = read(REPO_ROOT / "cengine.xcodeproj/project.pbxproj")
    build_script = read(REPO_ROOT / "Scripts/build-release.sh")
    makefile = read(REPO_ROOT / "Makefile")
    component_plist_path = REPO_ROOT / "Configuration/cengine-component.plist"
    for needle in (
        'PAYLOAD_ROOT/Applications', 'PAYLOAD_ROOT/usr/local/bin', 'dev.cengine.app.pkg',
        'Contents/Helpers/cengine', 'Contents/Helpers/cengine-network-helper',
        'Contents/Library/LaunchAgents', 'Contents/Library/LaunchDaemons',
        'cengine-uninstall.pkg', 'codesign --force',
        '--options runtime', 'productsign --sign', 'notarytool submit',
        'stapler staple', 'spctl --assess --type install', 'verify-entitlements.sh',
        "sed -nE 's/.*MARKETING_VERSION", 'xattr -cr "$PAYLOAD_ROOT"',
        'install_name_tool -delete_rpath', 'PackageFrameworks',
        '--component-plist "$COMPONENT_PLIST"',
    ):
        require_contains(script, needle, "package-release.sh")
    require_contains(entitlements, "com.apple.security.virtualization", "cengine.entitlements")
    require_absent(entitlements, "com.apple.developer.networking.vmnet", "cengine.entitlements")
    require_absent(entitlements, "com.apple.vm.networking", "cengine.entitlements")
    require_absent(app_entitlements, "com.apple.security.virtualization", "cengine-app.entitlements")
    for contents, label in ((script, "package-release.sh"), (build_script, "build-release.sh"), (makefile, "Makefile")):
        require_contains(contents, "CENGINE_GIT_COMMIT", label)
        require_contains(contents, "CENGINE_BUILD_TIME", label)
    require_contains(info_plist, "$(CENGINE_GIT_COMMIT)", "cengine-Info.plist")
    require_contains(info_plist, "$(CENGINE_BUILD_TIME)", "cengine-Info.plist")
    require_contains(info_plist, "$(CENGINE_TEAM_IDENTIFIER)", "cengine-Info.plist")
    require_contains(project, 'INFOPLIST_FILE = "Configuration/cengine-Info.plist"', "project.pbxproj")
    require_contains(project, "Configuration/cengine-app-Info.plist", "project.pbxproj")
    require_contains(project, "Configuration/network-helper-Info.plist", "project.pbxproj")
    require_contains(project, 'LD_RUNPATH_SEARCH_PATHS = ""', "project.pbxproj")
    if project.count("CREATE_INFOPLIST_SECTION_IN_BINARY = YES") != 4:
        raise AssertionError("engine and network helper builds must embed metadata")

    with component_plist_path.open("rb") as component_plist_file:
        components = plistlib.load(component_plist_file)
    app_component = next(
        component for component in components
        if component.get("RootRelativeBundlePath") == "Applications/cengine.app"
    )
    if app_component.get("BundleIsRelocatable") is not False:
        raise AssertionError("cengine.app must not be relocated away from /Applications")


if __name__ == "__main__":
    main()
