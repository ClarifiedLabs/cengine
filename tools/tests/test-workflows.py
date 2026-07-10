#!/usr/bin/env python3
from _checks import REPO_ROOT, read, require_absent, require_contains


def main() -> None:
    test = read(REPO_ROOT / ".github/workflows/test.yml")
    release = read(REPO_ROOT / ".github/workflows/release.yml")
    makefile = read(REPO_ROOT / "Makefile")
    for needle in ("- main", "- release-ci", "pull_request:", "workflow_dispatch:", "runs-on: macos-26", "make test"):
        require_contains(test, needle, "test.yml")
    for needle in (
        "- release-ci", "v*.*.*", "require-tests:", "needs: require-tests",
        "CENGINE_SIGN_RELEASE=1", "CENGINE_NOTARIZE=1", "./Scripts/package-release.sh",
        "gh release create", "homebrew-publish:", "ClarifiedLabs/homebrew-tap",
        "Upload package artifact",
    ):
        require_contains(release, needle, "release.yml")
    for forbidden in ("draft: true", "--draft", "TestFlight"):
        require_absent(release, forbidden, "release.yml")
    require_contains(
        makefile,
        'CENGINE_BINARY="$(XCODE_DERIVED_DATA)/Build/Products/Debug/cengine"',
        "Makefile",
    )


if __name__ == "__main__":
    main()
