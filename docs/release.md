# Release Process

cengine releases use one signed, notarized `.pkg` for direct downloads and the
Homebrew Cask in `ClarifiedLabs/homebrew-tap`.

## Workflows

`test.yml` runs for `main`, `release-ci`, pull requests, and manual dispatch.
`release.yml` runs for `release-ci`, `v*.*.*` tags, and manual dispatch. It waits
for a successful test run for the same commit before packaging.

`release-ci` exercises the full signing and notarization paths and uploads both
artifacts to Actions. It does not create a GitHub Release or update Homebrew.
Tag runs publish the package and update the Homebrew Cask to use it.

## Required Secrets

- `DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64`
- `DEVELOPER_ID_APPLICATION_CERTIFICATE_PASSWORD`
- `DEVELOPER_ID_INSTALLER_CERTIFICATE_BASE64`
- `DEVELOPER_ID_INSTALLER_CERTIFICATE_PASSWORD`
- `APP_STORE_CONNECT_KEY_ID`
- `APP_STORE_CONNECT_ISSUER_ID`
- `APP_STORE_CONNECT_PRIVATE_KEY`
- `HOMEBREW_TAP_APP_CLIENT_ID`
- `HOMEBREW_TAP_APP_PRIVATE_KEY`

The Homebrew GitHub App must have Contents read/write access to
`ClarifiedLabs/homebrew-tap`.

## Test a Release

```bash
git push origin HEAD:release-ci
```

The resulting `cengine-<version>.pkg` must pass nested signature inspection,
stapler validation, and Gatekeeper assessment.

## Create a Release

```bash
make release VERSION=patch
make release VERSION=minor
make release VERSION=major
make release VERSION=1.2.3
make release VERSION=patch DRY_RUN=1
make release VERSION=patch AUTOPUSH=1
```

The helper updates Xcode `MARKETING_VERSION`, creates a conventional release
commit when the version changes, and creates an annotated `vX.Y.Z` tag. The
first `VERSION=patch` release uses the project version `0.0.1`.

For a local payload-only package:

```bash
make package
pkgutil --payload-files dist/cengine-0.0.1.pkg
pkgutil --check-signature dist/cengine-0.0.1.pkg
```

Users open `cengine.app`; it registers the bundled engine LaunchAgent and offers
the optional privileged networking helper during onboarding.

The PKG installs `/Applications/cengine.app` and `/usr/local/bin/cengine` and
therefore requests administrator authorization. Homebrew installs the same PKG.
