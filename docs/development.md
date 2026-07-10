# Development

`cengine` is an Xcode project targeting arm64 macOS 26. The supported build
entrypoints are:

```bash
make build
make test
make test-compat
make dist-cli
make package
```

`make test` runs `CEngineCoreTests` and `CEngineAPITests` through the shared
`cengine` scheme. `make dist-cli` runs the tests and stages `dist/cengine`.
`make package` creates `dist/cengine-0.0.1.pkg` for local payload testing.

`make test-compat` builds the debug daemon, creates a cached Python virtual
environment under `.build`, and runs the Docker API and Docker Compose 5.3.1
compatibility suites against a temporary root and Unix socket. The command uses
the kernel installed by `cengine system install`; override it with
`CENGINE_KERNEL`, or override the daemon and fixture image with
`CENGINE_BINARY` and `CENGINE_TEST_IMAGE`. The suite requires Docker Compose
5.3.1; CI installs the checksum-pinned plugin with
`Scripts/install-compose-compat.sh`.

The CLI target is ad-hoc signed for local development with
`Configuration/cengine.entitlements`. That file intentionally contains only
`com.apple.security.virtualization`; the build rejects either vmnet entitlement.

The Xcode workspace owns Swift package resolution. Update and commit
`cengine.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`
when dependency versions change.
