# Release Process

cengine releases use one signed, notarized `.pkg` for direct downloads and the
Homebrew Cask in `ClarifiedLabs/homebrew-tap`.

## Workflows

`test.yml` runs for `main`, `release-ci`, pull requests, and manual dispatch.
`release.yml` runs for `release-ci`, `v*.*.*` tags, and manual dispatch. It waits
for a successful test run for the same commit before packaging. Normal guest
asset builds fetch the dedicated, checksum-verified kernel release rather than
compiling a kernel as part of every application release.

`kernel-release.yml` builds the kernel from its pinned source on Linux ARM64.
Manual dispatch uploads workflow artifacts without publishing. Pushing the
configured `kernel-v*` tag creates a dedicated GitHub Release containing
`cengine-kernel-arm64`, `kernel-input.sha256`, and `SHA256SUMS`; an existing
kernel release is never overwritten.

`release-ci` exercises the full signing and notarization paths and uploads the
guest assets and signed package as workflow artifacts. It does not create a
GitHub Release or update Homebrew. Tag runs publish the package and update the
Homebrew Cask to use it.

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

## Publish a Kernel Release

`Configuration/kernel-release` is the source of truth for the kernel release
consumed by `make kernel`, normal guest asset builds, and application release
CI. It is the only supported kernel release-tag setting and contains the
complete GitHub tag, such as `kernel-v6.18.35-2`. Use
`make release-list COMPONENT=kernel` to print the configured value. Change and
commit this file, together with any corresponding kernel inputs, to select a
different published release.

When changing the kernel version, commit, build image, config fragment, or build
scripts:

1. Update the kernel inputs under `Configuration/`, build with
   `make kernel-build`, and run the relevant compatibility tests locally.
2. Commit those changes and ensure the commit is on an up-to-date `main`.
3. Create the kernel release:

```bash
make release COMPONENT=kernel AUTOPUSH=1
```

When `VERSION` is omitted, the helper reads `Configuration/kernel-version`,
examines matching local and `origin` tags, and selects one revision above the
highest existing `kernel-v<source-version>-N` tag. For example, Linux `6.18.35`
uses `kernel-v6.18.35-1` when no matching tag exists, then
`kernel-v6.18.35-2` for the next release. The helper updates
`Configuration/kernel-release`, creates a conventional release commit when that
value changes, creates the matching annotated tag, and pushes the commit and
tag.

Use `VERSION=6.18.35-2` to choose an explicit tag suffix without `kernel-v`.
The application `patch`, `minor`, and `major` shortcuts remain unsupported for
kernel releases because they are ambiguous between a new Linux source version
and a cengine rebuild revision. Preview automatic resolution without changing
files, commits, tags, or remotes with:

```bash
make release COMPONENT=kernel DRY_RUN=1
```

The tagged commit must be on `main`. Wait for `kernel-release.yml` to publish the
assets before relying on `make kernel` or starting an application release. Use
`CENGINE_LOCAL_KERNEL=/path/to/Image make guest-assets` while testing an
unpublished kernel, or `CENGINE_KERNEL_MODE=build make guest-assets` to rebuild
from the configured source.

## Create an Application Release

The application is the default release component, so the existing commands are
unchanged (`COMPONENT=cengine` may be supplied explicitly):

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
`patch`, `minor`, and `major` forms increment the highest existing release tag.
When the repository has no release tag yet, they use the current Xcode project
version without incrementing it.

For a local unsigned package:

```bash
make package
pkgutil --payload-files dist/cengine-X.Y.Z.pkg
pkgutil --check-signature dist/cengine-X.Y.Z.pkg
```

Replace `X.Y.Z` with the Xcode project's current `MARKETING_VERSION`. The local
package is intentionally unsigned; `pkgutil --check-signature` reports that
state. CI produces the Developer ID signed, notarized, and stapled package.

The Homebrew Cask opens `cengine.app` with an installer-only argument after
installation and upgrades. A fresh install exits before showing the app or
registering services; the user opens cengine to begin onboarding. An upgrade or
standard reinstall resumes an explicitly enabled engine, with preserved service
state providing the one-time signal for upgrades from older releases. An active
`cengine` Docker context is restored on the next managed engine start. The
postflight launch is non-fatal so package installation still works in headless
sessions.

The PKG installs `/Applications/cengine.app` and `/usr/local/bin/cengine` and
therefore requests administrator authorization. Homebrew installs the same PKG
with its command-line installer, so `brew install` requests `sudo` rather than
showing Installer.app's authorization dialog. The package marks the app bundle
as non-relocatable so PackageKit always installs it at `/Applications/cengine.app`.
