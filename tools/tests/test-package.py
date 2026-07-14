#!/usr/bin/env python3
import plistlib

from _checks import REPO_ROOT, read, require_absent, require_contains


def main() -> None:
    script = read(REPO_ROOT / "Scripts/package-release.sh")
    entitlements = read(REPO_ROOT / "Configuration/cengine.entitlements")
    app_entitlements = read(REPO_ROOT / "Configuration/cengine-app.entitlements")
    component_plist = read(REPO_ROOT / "Configuration/cengine-component.plist")
    info_plist = read(REPO_ROOT / "Configuration/cengine-Info.plist")
    project = read(REPO_ROOT / "cengine.xcodeproj/project.pbxproj")
    build_script = read(REPO_ROOT / "Scripts/build-release.sh")
    makefile = read(REPO_ROOT / "Makefile")
    uninstall_distribution = read(REPO_ROOT / "Scripts/Uninstaller/Distribution.xml")
    uninstall_welcome = read(REPO_ROOT / "Scripts/Uninstaller/Resources/welcome.html")
    uninstall_conclusion = read(REPO_ROOT / "Scripts/Uninstaller/Resources/conclusion.html")
    component_plist_path = REPO_ROOT / "Configuration/cengine-component.plist"
    for needle in (
        'PAYLOAD_ROOT/Applications', 'PAYLOAD_ROOT/usr/local/bin', 'dev.cengine.app.pkg',
        'Contents/MacOS/cengine-engine', 'Contents/MacOS/cengine-network-helper',
        'Contents/Library/LaunchAgents', 'Contents/Library/LaunchDaemons',
        'cengine-uninstall.pkg', 'Contents/Resources/guest', 'codesign --force',
        '--options runtime', 'productsign --sign', 'notarytool submit',
        'stapler staple', 'spctl --assess --type install', 'verify-entitlements.sh',
        "sed -nE 's/.*MARKETING_VERSION", 'xattr -cr "$PAYLOAD_ROOT"',
        'install_name_tool -delete_rpath', 'PackageFrameworks',
        '--component-plist "$COMPONENT_PLIST"',
        'cengine-uninstall-component.pkg', '--distribution "$UNINSTALLER_DISTRIBUTION"',
        '--resources "$ROOT_DIR/Scripts/Uninstaller/Resources"', '--package-path "$BUILD_DIR"',
    ):
        require_contains(script, needle, "package-release.sh")
    for needle in (
        "<title>Uninstall cengine</title>", '<welcome file="welcome.html"',
        '<conclusion file="conclusion.html"', 'enable_localSystem="true"',
        "cengine-uninstall-component.pkg",
    ):
        require_contains(uninstall_distribution, needle, "uninstaller Distribution.xml")
    require_contains(uninstall_welcome, "Uninstall cengine", "uninstaller welcome")
    require_contains(
        uninstall_welcome, "does not install cengine or any other software", "uninstaller welcome"
    )
    require_contains(uninstall_conclusion, "cengine has been uninstalled", "uninstaller conclusion")
    require_contains(entitlements, "com.apple.security.virtualization", "cengine.entitlements")
    require_absent(entitlements, "com.apple.vm.networking", "cengine.entitlements")
    require_absent(entitlements, "com.apple.developer.networking.vmnet", "cengine.entitlements")
    if (REPO_ROOT / "Configuration/cengine-network-helper.entitlements").exists():
        raise AssertionError("the root network helper must not claim restricted vmnet entitlements")
    require_absent(script, "NETWORK_HELPER_ENTITLEMENTS", "package-release.sh")
    require_contains(script, 'verify-entitlements.sh" "$APP_PATH/Contents/MacOS/cengine-network-helper" --forbid com.apple.vm.networking', "package-release.sh")
    require_absent(app_entitlements, "com.apple.security.virtualization", "cengine-app.entitlements")
    require_contains(component_plist, "<key>BundleIsVersionChecked</key>\n\t\t<false/>", "cengine-component.plist")
    for contents, label in ((script, "package-release.sh"), (build_script, "build-release.sh"), (makefile, "Makefile")):
        require_contains(contents, "CENGINE_GIT_COMMIT", label)
        require_contains(contents, "CENGINE_BUILD_TIME", label)
    for contents, label in (
        (script, "package-release.sh"),
        (build_script, "build-release.sh"),
        (makefile, "Makefile"),
    ):
        require_contains(contents, "ENABLE_CODE_COVERAGE=NO", label)
        require_contains(contents, "CLANG_COVERAGE_MAPPING=NO", label)
    for contents, label in ((script, "package-release.sh"), (build_script, "build-release.sh")):
        require_contains(contents, "require_uninstrumented", label)
        require_contains(contents, "__llvm_prf", label)
    if project.count("CLANG_COVERAGE_MAPPING = NO") != 2 or project.count("ENABLE_CODE_COVERAGE = NO") != 2:
        raise AssertionError("shared Debug and Release build settings must disable coverage instrumentation")
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
