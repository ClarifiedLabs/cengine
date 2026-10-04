#!/usr/bin/env python3
"""Build-only ordinary lifecycle fault selector. Never used by running processes.

Runner API: `selection` validates the environment and prints empty or the profile;
`build-settings` prints four newline-separated xcodebuild arguments, including
explicit empty values for normal builds. Do not forward these to controller or
Guest builds. No global SWIFT_ACTIVE_COMPILATION_CONDITIONS override is needed.
"""
from __future__ import annotations

import os
import re
import sys

PROFILE = "before-configure-v1"
REPLACEMENT_PROFILE = "after-replacement-before-completion-v1"
TAKEOVER_PROFILES = ("before-takeover-apply-v1", "after-takeover-apply-v1")
COLD_L2_PROFILE = "after-cold-l2-before-a1-v1"
FIRST_COLD_COMPLETION_PROFILE = "after-first-cold-completion-v1"
PROFILES = (PROFILE, REPLACEMENT_PROFILE, *TAKEOVER_PROFILES, COLD_L2_PROFILE, FIRST_COLD_COMPLETION_PROFILE)
ENV = "CENGINE_COMPAT_LIFECYCLE_FAULT"
CONDITION_SETTING = "CENGINE_RUNTIME_COMPAT_LIFECYCLE_FAULT_CONDITION"
CONDITION = "CENGINE_COMPAT_LIFECYCLE_FAULT"
HELPER_CONDITION_SETTING = "CENGINE_HELPER_COMPAT_COLD_L2_FAULT_CONDITION"
COLD_L2_SETTING = "CENGINE_COMPAT_COLD_L2_FAULT"
HELPER_CONDITION = "CENGINE_COMPAT_COLD_L2_FAULT"


def selection(environment=None):
    env = os.environ if environment is None else environment
    # These are output settings, never additional caller-facing selectors.
    # Explicit empty build arguments also prevent stale Xcode activation.
    for key in (CONDITION_SETTING, HELPER_CONDITION_SETTING, COLD_L2_SETTING):
        if key in env:
            raise ValueError(f"{key} is reserved for validated build arguments")
    for key in ("CENGINE_COMPAT_SHARED_STORAGE", "CENGINE_COMPAT_MANAGED_STORAGE"):
        if key in env:
            raise ValueError(f"{key} is retired; lifecycle is the default")
    value = env.get(ENV, "")
    if value not in ("", *PROFILES):
        raise ValueError(f"{ENV} must be empty or one of {', '.join(PROFILES)}")
    if not value:
        return value
    if re.fullmatch(r"Developer ID Application: [^\r\n]+ \([A-Z0-9]{10}\)",
                    env.get("CENGINE_DEVELOPER_ID_APPLICATION", "")) is None:
        raise ValueError("lifecycle fault requires a full Developer ID Application identity")
    for key in ("CENGINE_STORAGE_LIFECYCLE_QUALIFICATION", "CENGINE_STORAGE_LIFECYCLE_SOURCE_PIN",
                "CENGINE_STORAGE_LIFECYCLE_ASSETS_SHA256", "CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY",
                "PREPARE_COMPATIBILITY_PROFILE"):
        if env.get(key):
            raise ValueError("lifecycle fault cannot combine qualification or PREPARE selections")
    for key in ("CONFIGURATION", "XCODE_COMPAT_CONFIGURATION", "XCODE_COMPAT_SCHEME"):
        if env.get(key) not in (None, "", "test-compat"):
            raise ValueError("lifecycle fault requires test-compat configuration and scheme")
    for key in ("CENGINE_SIGN_RELEASE", "CENGINE_NOTARIZE"):
        if env.get(key) not in (None, "", "0"):
            raise ValueError("lifecycle fault cannot select production/release signing")
    for key in ("CODE_SIGNING_ALLOWED", "CODE_SIGNING_REQUIRED"):
        if env.get(key) not in (None, "", "YES"):
            raise ValueError("lifecycle fault cannot disable signing")
    if "CODE_SIGN_IDENTITY" in env and not env["CODE_SIGN_IDENTITY"].startswith("Developer ID Application: "):
        raise ValueError("lifecycle fault cannot select unsigned/ad-hoc signing")
    return value


def build_settings(environment=None):
    value = selection(environment)
    helper_only = value == COLD_L2_PROFILE
    return [f"{ENV}={value}",
            f"{CONDITION_SETTING}={CONDITION if value and not helper_only else ''}",
            f"{HELPER_CONDITION_SETTING}={HELPER_CONDITION if helper_only else ''}",
            f"{COLD_L2_SETTING}={value if helper_only else ''}"]


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["selection"]:
            print(selection())
        elif sys.argv[1:] == ["build-settings"]:
            print("\n".join(build_settings()))
        else:
            raise ValueError("expected selection or build-settings")
    except ValueError as error:
        sys.exit(f"compatibility lifecycle fault refused: {error}")
