# Development

`cengine` is an Xcode project targeting arm64 macOS 26. The supported build
entrypoints are:

```bash
make build
make test
make dist-cli
make package
```

`make test` runs `CEngineCoreTests` and `CEngineAPITests` through the shared
`cengine` scheme. `make dist-cli` runs the tests and stages `dist/cengine`.
`make package` creates `dist/cengine-0.0.1.pkg` for local payload testing.

The CLI target is ad-hoc signed for local development with
`Configuration/cengine.entitlements`. That file intentionally contains only
`com.apple.security.virtualization`; the build rejects either vmnet entitlement.

The Xcode workspace owns Swift package resolution. Update and commit
`cengine.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`
when dependency versions change.
