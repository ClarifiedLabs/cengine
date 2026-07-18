# Repository Guidelines

## Project Structure & Module Organization

Swift sources live under `Sources/`: `CEngineCore` contains shared models and utilities, `CEngineRuntime` owns container lifecycle and Apple virtualization, `CEngineAPI` implements the Docker-compatible HTTP surface, `CEngineApp` is the macOS app, and `cengine` is the CLI entry point. Swift tests mirror these modules in `Tests/*Tests`. VM-backed Docker, Compose, Buildx, and recovery scenarios live in `Tests/Compatibility`, with fixtures in `Tests/Fixtures`. Release automation is split between `Scripts/` and `tools/`; configuration, entitlements, and plists are in `Configuration/`. Architecture and compatibility details belong in `docs/`.

## Build, Test, and Development Commands

Development requires Apple silicon and macOS 26 or newer.

- `make build` builds the shared `cengine` Xcode scheme in debug mode.
- `make test` checks the compatibility harness and runs the Swift/Xcode test suite.
- `make test-compat` builds the daemon and runs isolated pytest-based Docker compatibility tests.
- `make test-compat-soak` repeats compatibility tests with shuffled seeds.
- `make dist-cli` tests and stages the signed CLI in `dist/`.
- `make test-release` runs release-tooling regression checks.
- `make clean` removes `.build/` and `dist/` artifacts.

Use `cengine daemon --metadata-only` when developing API metadata without downloading a kernel or starting VMs.

## Coding Style & Naming Conventions

Follow existing Swift conventions: four-space indentation, `UpperCamelCase` types, `lowerCamelCase` members, and filenames matching their primary type. Prefer small, focused actors and value types; preserve Swift concurrency annotations such as `Sendable`. Python tests use `snake_case`. No repository-wide formatter or linter is configured, so match nearby code and keep imports minimal.

## Testing Guidelines

Use Swift Testing (`@Suite`, `@Test`, `#expect`) for unit tests and name files `*Tests.swift`. Bug fixes must include regression coverage. Compatibility tests are named `test_*.py`; each non-oracle test requires a unique `@pytest.mark.compat("AREA-NNN")` entry also recorded in `docs/docker-compatibility.md`. Run the narrowest relevant suite first, then `make test` before review. VM-backed changes should also run `make test-compat` locally. Runtime-semantic changes must cite the applicable Docker API, OCI Runtime, or Linux contract in `docs/docker-compatibility.md`, update its OCI applicability table when coverage changes, and add a focused `RTM-*` compatibility test before relying on kind or another application-level integration test.

## Commit & Pull Request Guidelines

Use Conventional Commits, as in `fix(network): accept Docker masquerade option` or `feat: configure default VM resources`. Keep commits scoped and imperative. Pull requests must be ready for review—never open drafts—and should explain behavior changes, list verification commands, link relevant issues, and include screenshots for app UI changes. Commit `Package.resolved` whenever dependency versions change.
