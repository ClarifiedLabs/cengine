SHELL := /bin/bash

VERSION ?=
SKIP_TESTS ?=
DRY_RUN ?=
AUTOPUSH ?= 0
RELEASE ?= ./tools/release.py
XCODEBUILD ?= xcodebuild
XCODE_PROJECT ?= cengine.xcodeproj
XCODE_DERIVED_DATA ?= .build/xcode-derived
XCODE_SOURCE_PACKAGES ?= .build/xcode-source-packages
XCODE_DESTINATION ?= platform=macOS,arch=arm64
XCODE_RESULT_BUNDLE ?=
CENGINE_GUEST_OUTPUT ?= $(CURDIR)/.build/guest
CENGINE_GIT_COMMIT ?= $(shell git rev-parse --short=7 HEAD 2>/dev/null || printf unknown)
CENGINE_BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
XCODE_COMMON_FLAGS = -clonedSourcePackagesDirPath "$(XCODE_SOURCE_PACKAGES)" -skipPackagePluginValidation -skipMacroValidation
XCODE_RESULT_BUNDLE_FLAGS = $(if $(XCODE_RESULT_BUNDLE),-resultBundlePath "$(XCODE_RESULT_BUNDLE)",)
XCODE_METADATA_FLAGS = CENGINE_GIT_COMMIT="$(CENGINE_GIT_COMMIT)" CENGINE_BUILD_TIME="$(CENGINE_BUILD_TIME)"
CENGINE_COMPAT_ENV = CENGINE_BINARY="$(XCODE_DERIVED_DATA)/Build/Products/Debug/cengine" \
	CENGINE_KERNEL="$(CENGINE_GUEST_OUTPUT)/vmlinux" \
	CENGINE_CONTAINER_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/container-initramfs.cpio.gz" \
	CENGINE_STORAGE_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/storage-initramfs.cpio.gz"

export CENGINE_GIT_COMMIT CENGINE_BUILD_TIME

.PHONY: all build guest-assets guest-initramfs kernel test test-guest test-compat test-compat-soak test-compat-oracle dist-cli package release release-list test-release clean help

all: dist-cli

help:
	@printf '%s\n' \
		'make               Run tests and build the signed dist/cengine binary' \
		'make build         Build cengine in debug mode with xcodebuild' \
		'make guest-assets  Build the cengine Linux guest binaries and initramfs' \
		'make guest-initramfs  Cross-compile the Linux guest binaries and rebuild initramfs' \
		'make kernel        Build the pinned cengine Linux kernel' \
		'make test          Run the Xcode test suite' \
		'make test-guest    Run Linux guest service unit tests' \
		'make test-compat  Run Docker API and Compose compatibility tests against an isolated daemon' \
		'make test-compat-soak  Run the compatibility suite three times with shuffled ordering' \
		'make test-compat-oracle  Compare deterministic contracts with DOCKER_REFERENCE_HOST' \
		'make dist-cli      Run tests and build the signed dist/cengine binary' \
		'make package       Build local unsigned PKG and DMG release artifacts' \
		'make release       Create a GitHub release tag (VERSION=patch|minor|major|X.Y.Z)' \
		'make release-list  List the current release tag' \
		'make test-release  Run release tooling regression checks' \
		'make clean         Remove build artifacts'

build:
	$(XCODEBUILD) -project "$(XCODE_PROJECT)" -scheme cengine -configuration Debug -derivedDataPath "$(XCODE_DERIVED_DATA)" $(XCODE_COMMON_FLAGS) $(XCODE_METADATA_FLAGS) build

guest-assets: kernel guest-initramfs

guest-initramfs:
	./Scripts/build-guest-assets.sh

kernel:
	./Scripts/build-kernel.sh

test:
	@python3 tools/tests/test-compat-harness.py
	$(XCODEBUILD) -project "$(XCODE_PROJECT)" -scheme cengine -configuration Debug -derivedDataPath "$(XCODE_DERIVED_DATA)" $(XCODE_COMMON_FLAGS) $(XCODE_METADATA_FLAGS) -destination '$(XCODE_DESTINATION)' $(XCODE_RESULT_BUNDLE_FLAGS) test

test-guest:
	./Scripts/test-guest.sh

test-compat: build guest-initramfs
	@Scripts/sign-compat-binary.sh .build/xcode-derived/Build/Products/Debug/cengine
	@python3 -m venv .build/compat-venv
	@.build/compat-venv/bin/pip install --disable-pip-version-check -q -r Tests/Compatibility/requirements.txt
	@$(CENGINE_COMPAT_ENV) \
		.build/compat-venv/bin/python -m pytest -c Tests/Compatibility/pytest.ini Tests/Compatibility

test-compat-soak: build guest-initramfs
	@Scripts/sign-compat-binary.sh .build/xcode-derived/Build/Products/Debug/cengine
	@python3 -m venv .build/compat-venv
	@.build/compat-venv/bin/pip install --disable-pip-version-check -q -r Tests/Compatibility/requirements.txt
	@for seed in 101 202 303; do \
		echo "Running compatibility soak seed $$seed"; \
		CENGINE_TEST_SEED="$$seed" $(CENGINE_COMPAT_ENV) \
			.build/compat-venv/bin/python -m pytest -c Tests/Compatibility/pytest.ini Tests/Compatibility || exit $$?; \
	done

test-compat-oracle: build guest-initramfs
	@test -n "$(DOCKER_REFERENCE_HOST)" || (echo 'DOCKER_REFERENCE_HOST is required' >&2; exit 2)
	@Scripts/sign-compat-binary.sh .build/xcode-derived/Build/Products/Debug/cengine
	@python3 -m venv .build/compat-venv
	@.build/compat-venv/bin/pip install --disable-pip-version-check -q -r Tests/Compatibility/requirements.txt
	@DOCKER_REFERENCE_HOST="$(DOCKER_REFERENCE_HOST)" $(CENGINE_COMPAT_ENV) \
		.build/compat-venv/bin/python -m pytest -c Tests/Compatibility/pytest.ini -m oracle Tests/Compatibility

dist-cli: test guest-assets
	XCODE_DERIVED_DATA="$(XCODE_DERIVED_DATA)" XCODE_SOURCE_PACKAGES="$(XCODE_SOURCE_PACKAGES)" ./Scripts/build-release.sh

package: guest-assets
	XCODE_DERIVED_DATA="$(XCODE_DERIVED_DATA)" XCODE_SOURCE_PACKAGES="$(XCODE_SOURCE_PACKAGES)" ./Scripts/package-release.sh

release-list:
	@$(RELEASE) list

release:
	@if [ -z "$(VERSION)" ]; then \
		echo "VERSION is required. Use: make release VERSION=<patch|minor|major|X.Y.Z>"; \
		exit 2; \
	fi
	@if [ -z "$(SKIP_TESTS)" ]; then \
		echo "Running release regression tests..."; \
		$(MAKE) --no-print-directory test-release; \
	fi
	@args=(release --version "$(VERSION)"); \
	if [ -n "$(DRY_RUN)" ]; then args+=(--dry-run); fi; \
	if [ "$(AUTOPUSH)" = "1" ]; then args+=(--push); fi; \
	$(RELEASE) "$${args[@]}"

test-release:
	@python3 tools/tests/test-release.py
	@python3 tools/tests/test-workflows.py
	@python3 tools/tests/test-homebrew-formula.py
	@python3 tools/tests/test-launchd-plists.py
	@python3 tools/tests/test-package.py

clean:
	rm -rf .build dist
