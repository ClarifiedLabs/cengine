#!/usr/bin/env python3
"""No installs, VMs, sudo, production executables or production route changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SUPPORT_MANIFEST = ROOT / "Configuration/helper-support-sources.txt"


def support_sources():
    return [ROOT / line for line in SUPPORT_MANIFEST.read_text().splitlines()]


def run(args, *, env, cwd=ROOT, timeout=900):
    print("+", " ".join(map(str, args)), flush=True)
    process = subprocess.Popen(args, cwd=cwd, env=env, start_new_session=True)
    try:
        code = process.wait(timeout=timeout)
    except BaseException:
        # A timed-out/interrupted leader has not been reaped by wait(). Kill the
        # owned group BEFORE joining it. Never signal a recycled process-group ID
        # after a completed wait; normal Swift teardown already joins its worker.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        raise
    if code:
        raise subprocess.CalledProcessError(code, args)


def closed_go_environment(base):
    compiler = {"CC", "CXX", "FC", "AR", "PKG_CONFIG", "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS",
                "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "LIBRARY_PATH"}
    env = {key: value for key, value in base.items()
           if not key.startswith(("GO", "CGO_")) and key not in compiler}
    env.update(GOFLAGS="-mod=vendor", GOWORK="off", GOENV="off", GOTOOLCHAIN="local",
               GOPROXY="off", GOSUMDB="off", CGO_ENABLED="0")
    return env


def source_hashes():
    inputs = [SUPPORT_MANIFEST] + list((ROOT / "Sources/CEngineCore").glob("*.swift"))
    inputs += list((ROOT / "Sources/CEngineNetworkHelper").glob("StorageBootstrap*.swift"))
    inputs += list((ROOT / "Guest/internal/storageauthority").glob("*.go"))
    inputs += [ROOT / "Guest/go.mod", ROOT / "Guest/go.sum"]
    # Include every vendored regular file, not just modules.txt: the closed Go
    # invocation below cannot substitute workspace/modules/toolchain downloads.
    for path in (ROOT / "Guest/vendor").rglob("*"):
        if path.is_symlink():
            raise RuntimeError("symlink in vendored inputs: " + str(path))
        if path.is_file():
            inputs.append(path)
    inputs += list((ROOT / "Sources/CEngineRuntime").glob("*.swift"))
    inputs += [path for path in (ROOT / "Tests/StorageLifecycleIntegrationTests").iterdir() if path.is_file()]
    inputs += [ROOT / "Tests/CEngineCoreTests/StorageLifecycleIntegratedTraceTests.swift"]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(set(inputs))}


def audit(hashes):
    if source_hashes() != hashes:
        raise RuntimeError("source inputs changed during run")


def exclusive_json(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(raw)
    return hashlib.sha256(raw).hexdigest()


def host_command(suite):
    return ["xcodebuild", "-project", "cengine.xcodeproj", "-scheme", "cengine", "-configuration", "Debug",
            "-derivedDataPath", str(ROOT / ".build/xcode-derived"), "-clonedSourcePackagesDirPath", str(ROOT / ".build/xcode-source-packages"),
            "-skipPackagePluginValidation", "-skipMacroValidation", "-destination", "platform=macOS,arch=arm64",
            "-only-testing:CEngineCoreTests/" + suite, "-parallel-testing-enabled", "NO",
            "OTHER_SWIFT_FLAGS=$(inherited) -D CENGINE_STORAGE_LIFECYCLE_INTEGRATION", "ENABLE_CODE_COVERAGE=NO", "test"]


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--producer-only", action="store_true", help="diagnostic only: does not claim host integration")
    mode.add_argument("--negative-only", action="store_true", help="small trace input tests; no lifecycle replay")
    args = parser.parse_args()
    build = ROOT / ".build"
    build.mkdir(exist_ok=True)
    # Retain PUBLIC evidence only. Private ROOT/Go journals live in the owned
    # temporary tree, including after abnormal process termination.
    evidence = Path(tempfile.mkdtemp(prefix="storage-lifecycle-integration-", dir=build))
    print("PUBLIC EVIDENCE:", evidence, flush=True)
    hashes = source_hashes()
    manifest_sha = exclusive_json(evidence / "source-hashes.json", hashes)
    audit(hashes)
    try:
        with tempfile.TemporaryDirectory(prefix="cengine-lifecycle-package-") as package_path:
            package = Path(package_path)
            temporary = package / "owned-temporary"
            temporary.mkdir(mode=0o700)
            env = dict(os.environ, TMPDIR=str(temporary), CENGINE_LIFECYCLE_WORKER=str(package / "guest-worker"),
                       CENGINE_LIFECYCLE_TRACE=str(evidence / "trace.ndjson"),
                       CENGINE_LIFECYCLE_MANIFEST_SHA256=manifest_sha, CENGINE_LIFECYCLE_SOURCE_COUNT=str(len(hashes)))
            if args.negative_only:
                run(host_command("StorageLifecycleTraceBoundaryTests"), env=env, timeout=1200)
            else:
                for name, files in [
                    ("Sources/CEngineHelperSupport", support_sources()),
                    ("Sources/StorageBootstrapHelper", sorted((ROOT / "Sources/CEngineNetworkHelper").glob("StorageBootstrap*.swift"))),
                    ("Tests/IntegrationTests", [ROOT / "Tests/StorageLifecycleIntegrationTests/ProducerTests.swift"]),
                ]:
                    destination = package / name
                    destination.mkdir(parents=True)
                    for source in files:
                        shutil.copy2(source, destination)
                        if name == "Tests/IntegrationTests":
                            # Producer and helper must use the same Swift DTO types.
                            copied = destination / source.name
                            copied.write_text(copied.read_text().replace("import CEngineCore", "import CEngineHelperSupport"))
                (package / "Package.swift").write_text('''// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "LifecycleIntegration", platforms: [.macOS(.v15)], targets: [
.target(name: "CEngineHelperSupport"),
.target(name: "StorageBootstrapHelper", dependencies: ["CEngineHelperSupport"]),
.testTarget(name: "IntegrationTests", dependencies: ["StorageBootstrapHelper", "CEngineHelperSupport"])
])
''')
                go_env = closed_go_environment(env)
                version = subprocess.check_output(["go", "version"], env=go_env, cwd=ROOT / "Guest", timeout=30).decode().strip()
                if not version.endswith("darwin/arm64"):
                    raise RuntimeError("requires local darwin/arm64 Go toolchain: " + version)
                run(["go", "test", "-tags=cengine_lifecycle_integration", "-c", "-o", env["CENGINE_LIFECYCLE_WORKER"],
                     "./internal/storageauthority"], env=go_env, cwd=ROOT / "Guest")
                worker_sha = hashlib.sha256(Path(env["CENGINE_LIFECYCLE_WORKER"]).read_bytes()).hexdigest()
                info = {"goVersion": version, "workerSHA256": worker_sha, "manifestSHA256": manifest_sha,
                        "sourceCount": len(hashes), "goEnvironment": {key: go_env[key] for key in
                        ["GOFLAGS", "GOWORK", "GOENV", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "CGO_ENABLED"]}}
                exclusive_json(evidence / "build-info.json", info)
                print("BUILD INFO:", json.dumps(info, sort_keys=True), flush=True)
                env.update(CENGINE_LIFECYCLE_WORKER_SHA256=worker_sha, CENGINE_LIFECYCLE_GO_VERSION=version)
                run(["swift", "test", "--package-path", str(package), "--filter", "StorageLifecycleIntegrationProducerTests"], env=env)
                if not args.producer_only:
                    env["TEST_RUNNER_CENGINE_LIFECYCLE_TRACE"] = env["CENGINE_LIFECYCLE_TRACE"]
                    run(host_command("StorageLifecycleIntegratedTraceTests"), env=env, timeout=1200)
    finally:
        audit(hashes)
    status = "NEGATIVE TESTS PASS" if args.negative_only else "PRODUCER PASS (host not run)" if args.producer_only else "PASS"
    print(status, evidence, flush=True)


if __name__ == "__main__":
    main()
