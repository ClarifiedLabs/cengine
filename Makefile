SHELL := /bin/bash

VERSION ?=
COMPONENT ?= cengine
SKIP_TESTS ?=
DRY_RUN ?=
AUTOPUSH ?= 0
RELEASE ?= ./tools/release.py
XCODEBUILD ?= xcodebuild
XCODE_PROJECT ?= cengine.xcodeproj
ifeq ($(CENGINE_STORAGE_LIFECYCLE_QUALIFICATION),lifecycle-v2-native-v1)
XCODE_DERIVED_DATA ?= $(CURDIR)/.build/lifecycle-v2-native-v1/xcode-derived
CENGINE_GUEST_OUTPUT ?= $(CURDIR)/.build/lifecycle-v2-native-v1/guest
endif
XCODE_DERIVED_DATA ?= .build/xcode-derived
XCODE_SOURCE_PACKAGES ?= .build/xcode-source-packages
XCODE_DESTINATION ?= platform=macOS,arch=arm64
XCODE_RESULT_BUNDLE ?=
XCODE_COMPAT_SCHEME ?= test-compat
XCODE_COMPAT_CONFIGURATION ?= test-compat
CENGINE_GUEST_OUTPUT ?= $(CURDIR)/.build/guest
CENGINE_GIT_COMMIT ?= $(shell git rev-parse --short=7 HEAD 2>/dev/null || printf unknown)
CENGINE_BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
CENGINE_HOST_OS ?= $(shell uname -s)
CENGINE_KERNEL_MODE ?= release
XCODE_COMMON_FLAGS = -clonedSourcePackagesDirPath "$(XCODE_SOURCE_PACKAGES)" -skipPackagePluginValidation -skipMacroValidation ENABLE_CODE_COVERAGE=NO CLANG_COVERAGE_MAPPING=NO
XCODE_RESULT_BUNDLE_FLAGS = $(if $(XCODE_RESULT_BUNDLE),-resultBundlePath "$(XCODE_RESULT_BUNDLE)",)
XCODE_METADATA_FLAGS = CENGINE_GIT_COMMIT="$(CENGINE_GIT_COMMIT)" CENGINE_BUILD_TIME="$(CENGINE_BUILD_TIME)"
CENGINE_COMPAT_ENV = XCODEBUILD="$(XCODEBUILD)" \
	XCODE_PROJECT="$(XCODE_PROJECT)" \
	XCODE_DERIVED_DATA="$(XCODE_DERIVED_DATA)" \
	XCODE_SOURCE_PACKAGES="$(XCODE_SOURCE_PACKAGES)" \
	XCODE_COMPAT_SCHEME="$(XCODE_COMPAT_SCHEME)" \
	XCODE_COMPAT_CONFIGURATION="$(XCODE_COMPAT_CONFIGURATION)" \
	CENGINE_BINARY="$(XCODE_DERIVED_DATA)/Build/Products/$(XCODE_COMPAT_CONFIGURATION)/cengine" \
	CENGINE_KERNEL="$(CENGINE_GUEST_OUTPUT)/vmlinux" \
	CENGINE_CONTAINER_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/container-initramfs.cpio.gz" \
	CENGINE_STORAGE_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/storage-initramfs.cpio.gz"
CENGINE_COMPAT_RESET = python3 Scripts/reset-compat-runtime.py --binary "$(XCODE_DERIVED_DATA)/Build/Products/$(XCODE_COMPAT_CONFIGURATION)/cengine"

export CENGINE_GIT_COMMIT CENGINE_BUILD_TIME CENGINE_HOST_OS

.PHONY: all build guest-assets guest-initramfs kernel kernel-build test test-guest test-compat test-compat-images test-compat-soak test-compat-oracle test-compat-reset test-compat-reset-system test-compat-doctor test-compat-helper-install test-compat-helper-uninstall dist-cli package release release-list test-release clean help

all: dist-cli

help:
	@printf '%s\n' \
		'make               Run tests and build the signed dist/cengine binary' \
		'make build         Build cengine in debug mode with xcodebuild' \
		'make guest-assets  Prepare the pinned kernel and build Linux guest initramfs files' \
		'make guest-initramfs  Cross-compile the Linux guest binaries and rebuild initramfs' \
		'make kernel        Fetch the pinned cengine Linux kernel release' \
		'make kernel-build  Build the pinned cengine Linux kernel from source' \
		'make test          Run the Xcode test suite' \
		'make test-guest    Run Linux guest service unit tests' \
		'make test-compat  Reset, rebuild, run Docker compatibility tests, and reset again' \
		'make test-compat-images  Explicitly download pinned local build image fixtures' \
		'make test-compat-soak  Run the compatibility suite three times with shuffled ordering' \
		'make test-compat-oracle  Compare deterministic contracts with DOCKER_REFERENCE_HOST' \
		'make test-compat-reset  Stop this worktree’s orphaned compatibility VMs and remove temporary roots' \
		'make test-compat-reset-system  Also restart vmnet system state after a helper crash' \
		'make test-compat-doctor  Check compatibility identities, helper health, and network pools' \
		'make test-compat-helper-install  Install or update the test helper (attended administrator action)' \
		'make test-compat-helper-uninstall  Remove the persistent compatibility helper' \
		'make dist-cli      Run tests and build the signed dist/cengine binary' \
		'make package       Build a local unsigned PKG release artifact' \
		'make release       Create a release tag (VERSION optional for COMPONENT=kernel)' \
		'make release-list  List the current release tag (COMPONENT=cengine|kernel)' \
		'make test-release  Run release tooling regression checks' \
		'make clean         Remove build artifacts'

build:
	$(XCODEBUILD) -project "$(XCODE_PROJECT)" -scheme cengine -configuration Debug -derivedDataPath "$(XCODE_DERIVED_DATA)" $(XCODE_COMMON_FLAGS) $(XCODE_METADATA_FLAGS) build

guest-assets: kernel
	./Scripts/build-guest-assets.sh

guest-initramfs: kernel
	./Scripts/build-guest-assets.sh

ifeq ($(CENGINE_KERNEL_MODE),build)
kernel: kernel-build
else ifeq ($(CENGINE_KERNEL_MODE),release)
kernel:
	./Scripts/fetch-kernel.sh
else
kernel:
	@echo "unsupported CENGINE_KERNEL_MODE=$(CENGINE_KERNEL_MODE); expected release or build" >&2
	@exit 2
endif

kernel-build:
	./Scripts/build-kernel.sh

test:
	@python3 tools/tests/test-compat-image-fixtures.py
	@python3 tools/tests/test-compose-local-fixtures.py
	@python3 tools/tests/test-sole-storage-startup.py
	@python3 tools/tests/test-helper-compatibility-policy.py
	@python3 tools/tests/test-helper-install-preservation.py
	@python3 tools/tests/test-network-helper-fingerprint.py
	@python3 tools/tests/test-managed-activation.py
	@python3 tools/tests/test-storage-lifecycle-qualification.py
	@python3 tools/tests/test-compat-lifecycle-fault.py
	@python3 tools/tests/test-storage-lifecycle-policy-boundaries.py
	@python3 tools/tests/test-storage-lifecycle-v2-runtime.py
	@python3 tools/tests/test-storage-guest-update.py
	@python3 tools/tests/test-storage-lifecycle-v2-remount.py
	@python3 tools/tests/test-guest-asset-provenance.py
	@python3 tools/tests/test-managed-retained-reader.py
	@python3 tools/tests/test-managed-root-backing.py
	@python3 tools/tests/test-managed-original-followup-parent.py
	@python3 tools/tests/test-managed-takeover-lifecycle-evidence.py
	@python3 tools/tests/test-managed-original-lifecycle-evidence.py
	@python3 tools/tests/test-managed-original-lifecycle-caller.py
	@python3 tools/tests/test-managed-original-lifecycle-peer.py
	@python3 tools/tests/test-rtm103-failure-diagnostic.py
	@python3 tools/tests/test-compat-harness.py
	@python3 tools/tests/test-compat-fixture-outcomes.py
	@python3 tools/tests/test-helper-fixture-lifetime.py
	@python3 tools/tests/test-tool-canonical-claims.py
	@python3 tools/tests/test-compat-default-assets.py
	@python3 tools/tests/test-isolated-cengine.py
	@python3 tools/tests/test-managed-prepare-faults.py
	@python3 tools/tests/test-managed-prepare-early.py
	@python3 tools/tests/test-managed-prepare-full.py
	@python3 tools/tests/test-managed-prepare-service.py
	@python3 tools/tests/test-managed-prepare-lifecycle-evidence.py
	@python3 tools/tests/test-managed-prepare-worker.py
	@python3 tools/tests/test-managed-prepare-peer-refresh.py
	@python3 tools/tests/test-managed-prepare-worker-lifecycle-evidence.py
	@python3 tools/tests/test-managed-prepare-storage-vm.py
	@python3 tools/tests/test-managed-prepare-active-ack.py
	@python3 tools/tests/test-managed-prepare-vm-active-ack.py
	@python3 tools/tests/test-managed-prepare-vm-exits.py
	@python3 tools/tests/test-managed-prepare-vm-boundaries.py
	@python3 tools/tests/test-managed-prepare-vm-parent.py
	@python3 tools/tests/test-managed-prepare-vm-runner.py
	@python3 tools/tests/test-managed-prepare-io.py
	@python3 tools/tests/test-managed-prepare-io-runner.py
	@python3 tools/tests/test-managed-prepare-restart-matrix.py
	@python3 tools/tests/test-managed-prepare-matrix.py
	@python3 tools/tests/test-managed-prepare-two-volume-drain.py
	@python3 tools/tests/test-managed-prepare-two-volume-parent.py
	@python3 tools/tests/test-managed-prepare-two-volume-runner.py
	@python3 tools/tests/test-managed-prepare-two-volume-restart.py
	@python3 tools/tests/test-managed-prepare-start-diagnostic.py
	@python3 tools/tests/test-prepare-compatibility-assets.py
	@python3 tools/tests/test-prepare-early-assets.py
	@python3 tools/tests/test-prepare-full-assets.py
	@python3 tools/tests/test-prepare-lifecycle-selection.py
	$(XCODEBUILD) -project "$(XCODE_PROJECT)" -scheme cengine -configuration Debug -derivedDataPath "$(XCODE_DERIVED_DATA)" $(XCODE_COMMON_FLAGS) $(XCODE_METADATA_FLAGS) -destination '$(XCODE_DESTINATION)' $(XCODE_RESULT_BUNDLE_FLAGS) test

ifeq ($(CENGINE_HOST_OS),Darwin)
test-guest: build guest-initramfs
endif

test-guest:
	./Scripts/test-guest.sh

test-compat-images:
	@python3 tools/compat_image_fixtures.py prepare python buildkit alpine

test-compat:
	@$(CENGINE_COMPAT_ENV) Scripts/run-compat-tests.sh suite $(COMPAT_ARGS)

test-compat-soak:
	@$(CENGINE_COMPAT_ENV) Scripts/run-compat-tests.sh soak $(COMPAT_ARGS)

test-compat-oracle:
	@DOCKER_REFERENCE_HOST="$(DOCKER_REFERENCE_HOST)" $(CENGINE_COMPAT_ENV) Scripts/run-compat-tests.sh oracle $(COMPAT_ARGS)

test-compat-reset:
	@$(CENGINE_COMPAT_RESET)

test-compat-reset-system:
	@$(CENGINE_COMPAT_RESET) --system-networking

test-compat-doctor:
	@$(CENGINE_COMPAT_ENV) Scripts/compat-doctor.sh

test-compat-helper-install:
	@$(CENGINE_COMPAT_ENV) Scripts/run-compat-tests.sh helper-install

test-compat-helper-uninstall:
	@. Scripts/compat-network-helper.sh && compat_network_helper_uninstall

dist-cli: test guest-assets
	XCODE_DERIVED_DATA="$(XCODE_DERIVED_DATA)" XCODE_SOURCE_PACKAGES="$(XCODE_SOURCE_PACKAGES)" ./Scripts/build-release.sh

package: guest-assets
	XCODE_DERIVED_DATA="$(XCODE_DERIVED_DATA)" XCODE_SOURCE_PACKAGES="$(XCODE_SOURCE_PACKAGES)" ./Scripts/package-release.sh

release-list:
	@$(RELEASE) list --component "$(COMPONENT)"

release:
	@if [ -z "$(VERSION)" ] && [ "$(COMPONENT)" != "kernel" ]; then \
		echo "VERSION is required for cengine releases. Use X.Y.Z, patch, minor, or major."; \
		exit 2; \
	fi
	@if [ -z "$(SKIP_TESTS)" ]; then \
		echo "Running release regression tests..."; \
		$(MAKE) --no-print-directory test-release; \
	fi
	@args=(release --component "$(COMPONENT)"); \
	if [ -n "$(VERSION)" ]; then args+=(--version "$(VERSION)"); fi; \
	if [ -n "$(DRY_RUN)" ]; then args+=(--dry-run); fi; \
	if [ "$(AUTOPUSH)" = "1" ]; then args+=(--push); fi; \
	$(RELEASE) "$${args[@]}"

test-release:
	@python3 tools/tests/test-guest-asset-provenance.py
	@python3 tools/tests/test-release.py
	@python3 tools/tests/test-workflows.py
	@python3 tools/tests/test_guest_build_scripts.py
	@python3 tools/tests/test-homebrew-formula.py
	@python3 tools/tests/test-launchd-plists.py
	@python3 tools/tests/test-package.py
	@python3 tools/tests/test-installer.py

clean:
	rm -rf .build dist
