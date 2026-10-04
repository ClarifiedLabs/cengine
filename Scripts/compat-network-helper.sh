#!/bin/sh
# Persistent compatibility-test Privileged Helper lifecycle.
# Deployed Mach-service IDs and protected namespace paths intentionally retain
# their historical network-helper spelling; executable/UI names do not.
# Source this file from compatibility runners; do not execute it directly.

compat_network_helper_service_name="dev.cengine.network-helper.test-compat"
compat_network_helper_label="dev.cengine.network-helper.test-compat"
compat_network_helper_protocol_version=5
compat_network_helper_support_root="/Library/Application Support/cengine"
compat_network_helper_parent="$compat_network_helper_support_root/compat"
compat_network_helper_root="/Library/Application Support/cengine/compat/dev.cengine.network-helper.test-compat"
compat_network_helper_path="$compat_network_helper_root/cengine-helper"
compat_network_helper_token_path="$compat_network_helper_root/client-token"
compat_network_helper_manifest_path="$compat_network_helper_root/manifest"
compat_network_helper_plist="/Library/LaunchDaemons/dev.cengine.network-helper.test-compat.plist"

compat_network_helper_local_for_binary() {
    _cnh_binary_dir=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd) || return 1
    printf '%s/cengine-helper\n' "$_cnh_binary_dir"
}

compat_network_helper_validate_fingerprint() {
    case "$1" in
        ""|*[!0123456789abcdef]*)
            echo "invalid compatibility Privileged Helper fingerprint: $1" >&2
            return 2
            ;;
    esac
    [ "${#1}" -eq 64 ] || {
        echo "compatibility Privileged Helper fingerprint must contain 64 hexadecimal characters" >&2
        return 2
    }
}

# Elevation uses terminal sudo: the previous osascript GUI administrator
# prompt fails outright in sessions without window-server access (SSH,
# detached tmux), while sudo prompts on any terminal.
compat_network_helper_run_as_administrator() {
    _cnh_script=$1
    shift
    /usr/bin/sudo /bin/sh -c "$_cnh_script" cengine-compat-helper "$@"
}

compat_network_helper_export_environment() {
    CENGINE_NETWORK_HELPER_SERVICE_NAME=$compat_network_helper_service_name
    CENGINE_NETWORK_HELPER_IDENTIFIER=dev.cengine.network-helper.test-compat
    CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE=$compat_network_helper_token_path
    CENGINE_COMPAT_NETWORK_HELPER_LABEL=$compat_network_helper_label
    CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT=$1
    export CENGINE_NETWORK_HELPER_SERVICE_NAME
    export CENGINE_NETWORK_HELPER_IDENTIFIER
    export CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE
    export CENGINE_COMPAT_NETWORK_HELPER_LABEL
    export CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT
}

compat_network_helper_installed_fingerprint() {
    [ -r "$compat_network_helper_manifest_path" ] || return 1
    /usr/bin/awk -F= '$1 == "fingerprint" { print $2; exit }' \
        "$compat_network_helper_manifest_path"
}

compat_network_helper_installed_owner() {
    [ -r "$compat_network_helper_manifest_path" ] || return 1
    /usr/bin/awk -F= '$1 == "owner_uid" { print $2; exit }' \
        "$compat_network_helper_manifest_path"
}

compat_network_helper_installed_sha256() {
    [ -r "$compat_network_helper_manifest_path" ] || return 1
    /usr/bin/awk -F= '$1 == "helper_sha256" { print $2; exit }' \
        "$compat_network_helper_manifest_path"
}

compat_network_helper_validate_sha256() {
    case "$1" in
        ""|*[!0123456789abcdef]*)
            echo "invalid compatibility Privileged Helper SHA-256: $1" >&2
            return 2
            ;;
    esac
    [ "${#1}" -eq 64 ] || {
        echo "compatibility Privileged Helper SHA-256 must contain 64 hexadecimal characters" >&2
        return 2
    }
}

compat_network_helper_validate_root_controlled() {
    _cnh_controlled_path=$1
    [ ! -L "$_cnh_controlled_path" ] || {
        echo "compatibility Privileged Helper path must not be a symbolic link: $_cnh_controlled_path" >&2
        return 1
    }
    _cnh_controlled_owner=$(/usr/bin/stat -f '%u' "$_cnh_controlled_path") || return 1
    [ "$_cnh_controlled_owner" = 0 ] || {
        echo "compatibility Privileged Helper path is not owned by root: $_cnh_controlled_path" >&2
        return 1
    }
    _cnh_controlled_permissions=$(/usr/bin/stat -f '%Sp' "$_cnh_controlled_path") || return 1
    case "$_cnh_controlled_permissions" in
        ?????w????*|????????w?*)
            echo "compatibility Privileged Helper path is group- or world-writable: $_cnh_controlled_path" >&2
            return 1
            ;;
    esac
}

compat_network_helper_validate_installation() {
    _cnh_expected_owner=$(id -u)
    for _cnh_controlled_path in \
        "$compat_network_helper_support_root" \
        "$compat_network_helper_parent" \
        "$compat_network_helper_root"; do
        [ -d "$_cnh_controlled_path" ] || {
            echo "compatibility Privileged Helper directory is missing: $_cnh_controlled_path" >&2
            return 1
        }
    done
    [ -x "$compat_network_helper_path" ] || {
        echo "compatibility Privileged Helper executable is missing: $compat_network_helper_path" >&2
        return 1
    }
    [ -r "$compat_network_helper_token_path" ] || {
        echo "compatibility Privileged Helper token is missing or unreadable: $compat_network_helper_token_path" >&2
        return 1
    }
    [ -f "$compat_network_helper_manifest_path" ] || {
        echo "compatibility Privileged Helper manifest is missing: $compat_network_helper_manifest_path" >&2
        return 1
    }
    [ -f "$compat_network_helper_plist" ] || {
        echo "compatibility Privileged Helper plist is missing: $compat_network_helper_plist" >&2
        return 1
    }

    for _cnh_controlled_path in \
        "$compat_network_helper_support_root" \
        "$compat_network_helper_parent" \
        "$compat_network_helper_root" \
        "$compat_network_helper_path" \
        "$compat_network_helper_manifest_path" \
        "$compat_network_helper_plist"; do
        compat_network_helper_validate_root_controlled "$_cnh_controlled_path" || return $?
    done

    /usr/bin/codesign --verify --strict "$compat_network_helper_path" >/dev/null 2>&1 || {
        echo "compatibility Privileged Helper has an invalid code signature" >&2
        return 1
    }

    _cnh_installed_owner=$(compat_network_helper_installed_owner 2>/dev/null || true)
    [ "$_cnh_installed_owner" = "$_cnh_expected_owner" ] || {
        echo "compatibility Privileged Helper is provisioned for UID ${_cnh_installed_owner:-missing}, not $_cnh_expected_owner" >&2
        return 1
    }
    _cnh_installed_fingerprint=$(compat_network_helper_installed_fingerprint 2>/dev/null || true)
    compat_network_helper_validate_fingerprint "$_cnh_installed_fingerprint" || return $?
    _cnh_installed_sha=$(compat_network_helper_installed_sha256 2>/dev/null || true)
    compat_network_helper_validate_sha256 "$_cnh_installed_sha" || return $?
    _cnh_actual_sha=$(/usr/bin/shasum -a 256 "$compat_network_helper_path" | /usr/bin/awk '{ print $1 }')
    [ "$_cnh_installed_sha" = "$_cnh_actual_sha" ] || {
        echo "compatibility Privileged Helper does not match its installed manifest" >&2
        return 1
    }

    [ ! -L "$compat_network_helper_token_path" ] || {
        echo "compatibility Privileged Helper token must not be a symbolic link" >&2
        return 1
    }
    _cnh_token_owner=$(/usr/bin/stat -f '%u' "$compat_network_helper_token_path") || return 1
    _cnh_token_mode=$(/usr/bin/stat -f '%Lp' "$compat_network_helper_token_path") || return 1
    [ "$_cnh_token_owner" = "$_cnh_expected_owner" ] || {
        echo "compatibility Privileged Helper token is not owned by UID $_cnh_expected_owner" >&2
        return 1
    }
    [ "$_cnh_token_mode" = 600 ] || {
        echo "compatibility Privileged Helper token mode is $_cnh_token_mode, expected 600" >&2
        return 1
    }

    /bin/launchctl print "system/$compat_network_helper_label" >/dev/null 2>&1 || {
        echo "compatibility Privileged Helper LaunchDaemon is not loaded" >&2
        return 1
    }
}

compat_network_helper_matches_local_build() {
    _cnh_helper=$1
    _cnh_fingerprint=$2
    compat_network_helper_validate_installation >/dev/null 2>&1 || return 1
    _cnh_installed=$(compat_network_helper_installed_fingerprint 2>/dev/null || true)
    [ "$_cnh_installed" = "$_cnh_fingerprint" ] || return 1
    _cnh_installed_sha=$(compat_network_helper_installed_sha256 2>/dev/null || true)
    _cnh_local_sha=$(/usr/bin/shasum -a 256 "$_cnh_helper" | /usr/bin/awk '{ print $1 }')
    [ "$_cnh_installed_sha" = "$_cnh_local_sha" ]
}

compat_network_helper_prepare_token() {
    _cnh_token=$1
    if [ -r "$compat_network_helper_token_path" ]; then
        /bin/cp "$compat_network_helper_token_path" "$_cnh_token"
    else
        /usr/bin/uuidgen | /usr/bin/tr -d '-' > "$_cnh_token"
    fi
    /bin/chmod 600 "$_cnh_token"
}

compat_network_helper_install() {
    _cnh_helper=$1
    _cnh_fingerprint=$2
    _cnh_owner_uid=$(id -u)
    _cnh_helper_sha=$(/usr/bin/shasum -a 256 "$_cnh_helper" | /usr/bin/awk '{ print $1 }')
    _cnh_temporary=$(mktemp -d "${TMPDIR:-/tmp}/cengine-compat-helper.XXXXXX") || return 1
    _cnh_temp_plist="$_cnh_temporary/helper.plist"
    _cnh_temp_manifest="$_cnh_temporary/manifest"
    _cnh_temp_token="$_cnh_temporary/client-token"

    compat_network_helper_prepare_token "$_cnh_temp_token"
    /usr/bin/printf '%s\n' \
        '<?xml version="1.0" encoding="UTF-8"?>' \
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
        '<plist version="1.0"><dict>' \
        "<key>Label</key><string>$compat_network_helper_label</string>" \
        "<key>ProgramArguments</key><array><string>$compat_network_helper_path</string></array>" \
        "<key>MachServices</key><dict><key>$compat_network_helper_service_name</key><true/></dict>" \
        '<key>EnvironmentVariables</key><dict>' \
        "<key>CENGINE_NETWORK_HELPER_SERVICE_NAME</key><string>$compat_network_helper_service_name</string>" \
        '<key>CENGINE_NETWORK_HELPER_CLIENT_IDENTIFIER</key><string>dev.cengine.engine.test-compat</string>' \
        "<key>CENGINE_NETWORK_HELPER_BUILD_FINGERPRINT</key><string>$_cnh_fingerprint</string>" \
        "<key>CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE</key><string>$compat_network_helper_token_path</string>" \
        "<key>CENGINE_NETWORK_HELPER_OWNER_UID</key><string>$_cnh_owner_uid</string>" \
        '<key>CENGINE_NETWORK_HELPER_TEST_CONTROL</key><string>1</string>' \
        '</dict>' \
        '<key>ProcessType</key><string>Interactive</string>' \
        '<key>StandardOutPath</key><string>/Library/Logs/cengine/dev.cengine.network-helper.test-compat.out.log</string>' \
        '<key>StandardErrorPath</key><string>/Library/Logs/cengine/dev.cengine.network-helper.test-compat.err.log</string>' \
        '</dict></plist>' > "$_cnh_temp_plist"
    /usr/bin/printf 'fingerprint=%s\nowner_uid=%s\nhelper_sha256=%s\n' \
        "$_cnh_fingerprint" "$_cnh_owner_uid" "$_cnh_helper_sha" > "$_cnh_temp_manifest"
    /usr/bin/plutil -lint "$_cnh_temp_plist" >/dev/null

    echo "installing compatibility Privileged Helper $compat_network_helper_label" >&2
    if compat_network_helper_run_as_administrator '
set -eu
root=$1
helper=$2
target=$3
token_source=$4
token_target=$5
manifest_source=$6
manifest_target=$7
plist_source=$8
plist_target=$9
label=${10}
owner_uid=${11}
compat_root=$(/usr/bin/dirname "$root")
support_root=$(/usr/bin/dirname "$compat_root")
support_parent=$(/usr/bin/dirname "$support_root")
log_dir=/Library/Logs/cengine
backup_root="$root.rollback.$$"
backup_plist="$plist_target.rollback.$$"
had_root=0
had_plist=0
installed=0
# Never recursively delete a helper root: it can contain protected authority.
remove_installation_files() {
    directory=$1
    /bin/rm -f "$directory/cengine-network-helper" "$directory/cengine-helper" \
        "$directory/client-token" "$directory/manifest" || return 1
    /bin/rmdir "$directory"
}
rollback() {
    status=$?
    trap - 0 1 2 15
    if [ "$installed" -eq 0 ]; then
        /bin/launchctl bootout "system/$label" >/dev/null 2>&1 || true
        if [ -d "$backup_root" ]; then
            if [ -e "$root/storage-lifecycle-v2" ] || [ -L "$root/storage-lifecycle-v2" ]; then
                # Restore authority before deleting any installation files. If a
                # rename fails, retain both roots for recovery, never erase either.
                if [ -e "$backup_root/storage-lifecycle-v2" ] || [ -L "$backup_root/storage-lifecycle-v2" ]; then
                    echo "refusing to overwrite protected helper state during rollback" >&2
                    exit 1
                fi
                /bin/mv "$root/storage-lifecycle-v2" "$backup_root/storage-lifecycle-v2" || exit 1
            fi
            if [ -d "$root" ]; then remove_installation_files "$root" || exit 1; fi
            /bin/mv "$backup_root" "$root" || exit 1
        elif [ "$had_root" -eq 0 ] && [ -d "$root" ]; then
            # A first startup may have created authority. Retain it, even when
            # startup fails; installing is never authority-reset authorization.
            if [ ! -e "$root/storage-lifecycle-v2" ] && [ ! -L "$root/storage-lifecycle-v2" ]; then
                remove_installation_files "$root" || exit 1
            fi
        fi
        if [ -e "$backup_plist" ] || [ -L "$backup_plist" ]; then
            /bin/rm -f "$plist_target" || exit 1
            /bin/mv "$backup_plist" "$plist_target" || exit 1
        elif [ "$had_plist" -eq 0 ]; then
            /bin/rm -f "$plist_target" || exit 1
        fi
        if [ "$had_plist" -eq 1 ]; then
            /bin/launchctl bootstrap system "$plist_target" >/dev/null 2>&1 || true
        fi
    fi
    if [ -d "$backup_root" ]; then remove_installation_files "$backup_root" || exit 1; fi
    /bin/rm -f "$backup_plist"
    exit "$status"
}
validate_controlled_directory() {
    directory=$1
    if [ -L "$directory" ] || [ ! -d "$directory" ]; then
        echo "helper support path is not a real directory: $directory" >&2
        return 1
    fi
    owner=$(/usr/bin/stat -f "%u" "$directory")
    permissions=$(/usr/bin/stat -f "%Sp" "$directory")
    if [ "$owner" != 0 ]; then
        echo "helper support directory is not owned by root: $directory" >&2
        return 1
    fi
    case "$permissions" in
        ?????w????*|????????w?*)
            echo "helper support directory is group- or world-writable: $directory" >&2
            return 1
            ;;
    esac
}
validate_controlled_directory "$support_parent"
for directory in "$support_root" "$compat_root"; do
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
        /bin/mkdir "$directory"
        /usr/sbin/chown root:wheel "$directory"
        /bin/chmod 755 "$directory"
    fi
    validate_controlled_directory "$directory"
done
# Only installer-owned files and the protected v2 directory are understood.
# Reject unexpected layouts before stopping the service or moving any old data.
if [ -e "$root" ] || [ -L "$root" ]; then
    validate_controlled_directory "$root"
    for entry in "$root"/* "$root"/.[!.]* "$root"/..?*; do
        if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then continue; fi
        case "${entry##*/}" in
            storage-lifecycle-v2) validate_controlled_directory "$entry" ;;
            cengine-network-helper|cengine-helper|client-token|manifest)
                if [ -L "$entry" ] || [ ! -f "$entry" ]; then
                    echo "helper installation entry is not a regular file: $entry" >&2
                    exit 1
                fi
                ;;
            *) echo "refusing unknown helper installation entry: $entry" >&2; exit 1 ;;
        esac
    done
    had_root=1
fi
if [ -e "$plist_target" ] || [ -L "$plist_target" ]; then had_plist=1; fi
# A killed installer cannot run rollback. Refuse backups from ANY prior PID,
# otherwise a retry could start with fresh authority while the old one is stranded.
for backup in "$root".rollback.* "$plist_target".rollback.*; do
    if [ -e "$backup" ] || [ -L "$backup" ]; then
        echo "refusing interrupted helper installation; retain and reconcile backup before retry: $backup" >&2
        exit 1
    fi
done
trap rollback 0
trap "exit 1" 1 2 15
/bin/launchctl bootout "system/$label" >/dev/null 2>&1 || true
if [ "$had_root" -eq 1 ]; then /bin/mv "$root" "$backup_root"; fi
if [ "$had_plist" -eq 1 ]; then /bin/mv "$plist_target" "$backup_plist"; fi
/bin/mkdir "$root"
/bin/mkdir -p "$log_dir"
/usr/bin/ditto --norsrc --noextattr "$helper" "$target"
/bin/cp "$token_source" "$token_target"
/bin/cp "$manifest_source" "$manifest_target"
/bin/cp "$plist_source" "$plist_target"
/usr/sbin/chown root:wheel "$root" "$target" "$token_target" "$manifest_target" "$plist_target"
/usr/sbin/chown "$owner_uid" "$token_target"
/bin/chmod 755 "$root" "$target"
/bin/chmod 600 "$token_target"
/bin/chmod 644 "$manifest_target" "$plist_target"
/usr/bin/codesign --verify --strict "$target"
/usr/bin/plutil -lint "$plist_target" >/dev/null
if [ -d "$backup_root/storage-lifecycle-v2" ]; then
    # Same-filesystem rename preserves every inode, byte, mode and owner. Do
    # not copy, migrate, chmod or chown authority as part of helper installation.
    /bin/mv "$backup_root/storage-lifecycle-v2" "$root/storage-lifecycle-v2"
fi
/bin/launchctl bootstrap system "$plist_target"
/bin/launchctl kickstart "system/$label"
/bin/sleep 1
/bin/launchctl print "system/$label" >/dev/null
installed=1
' "$compat_network_helper_root" "$_cnh_helper" "$compat_network_helper_path" \
        "$_cnh_temp_token" "$compat_network_helper_token_path" \
        "$_cnh_temp_manifest" "$compat_network_helper_manifest_path" \
        "$_cnh_temp_plist" "$compat_network_helper_plist" \
        "$compat_network_helper_label" "$_cnh_owner_uid"; then
        _cnh_status=0
    else
        _cnh_status=$?
    fi
    /bin/rm -rf "$_cnh_temporary"
    return "$_cnh_status"
}

compat_network_helper_print_install_instruction() {
    echo "install or update it with the attended command: make test-compat-helper-install" >&2
}

# Requirements only become stricter through environment selections. Capabilities
# and the security floor come from the signed client and authenticated live helper,
# never a manifest or caller-supplied version. All managed callers share this gate.
compat_network_helper_select_policy() {
    case "${CENGINE_COMPAT_REQUIRE_EXACT_HELPER:-}" in
        ''|1) ;;
        *) echo 'CENGINE_COMPAT_REQUIRE_EXACT_HELPER must be empty or 1' >&2; return 2;;
    esac
    if [ "${CENGINE_COMPAT_SHARED_STORAGE+x}${CENGINE_COMPAT_MANAGED_STORAGE+x}" != '' ]; then
        echo 'retired compatibility storage selector; lifecycle is the default' >&2; return 2
    fi
    _cnh_policy_root=${ROOT:-${ROOT_DIR:-}}
    [ -n "$_cnh_policy_root" ] && [ -f "$_cnh_policy_root/Scripts/helper_compatibility_policy.py" ] || {
        echo 'managed helper policy requires the checkout policy script' >&2; return 2;
    }
    python3 "$_cnh_policy_root/Scripts/helper_compatibility_policy.py" \
        "${CENGINE_STORAGE_LIFECYCLE_QUALIFICATION:-}" \
        "${CENGINE_COMPAT_LIFECYCLE_FAULT:-}" "${CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY:-}" \
        "${PREPARE_COMPATIBILITY_PROFILE:-}" "${CENGINE_COMPAT_REQUIRE_EXACT_HELPER:-}" \
        "${CENGINE_COMPAT_MANAGED_ASSET_DIR:-}"

}

compat_network_helper_require_exact() {
    _cnh_exact_binary=$1 _cnh_exact_fingerprint=$2
    compat_network_helper_validate_fingerprint "$_cnh_exact_fingerprint" || return $?
    _cnh_exact_helper=$(compat_network_helper_local_for_binary "$_cnh_exact_binary") || return $?
    # The installed full file still must match its root-owned manifest SHA-256.
    # CMS signingTime changes on re-sign; exact qualification compares the full
    # authenticated SHA-256 CodeDirectory, not CMS bytes or a truncated CDHash.
    [ "$(compat_network_helper_installed_fingerprint)" = "$_cnh_exact_fingerprint" ] &&
        _cnh_local_code=$(compat_network_helper_code_digest "$_cnh_exact_helper") &&
        _cnh_installed_code=$(compat_network_helper_code_digest "$compat_network_helper_path") &&
        [ "$_cnh_local_code" = "$_cnh_installed_code" ] || {
        echo 'helper qualification requires the exact locally built installed helper fingerprint and signed code digest' >&2
        compat_network_helper_print_install_instruction
        return 1
    }
}

compat_network_helper_require_managed() {
    _cnh_managed_binary=$1 _cnh_managed_fingerprint=$2 _cnh_managed_policy=${3:-exact}
    case "$_cnh_managed_policy" in
        exact) compat_network_helper_require_exact "$_cnh_managed_binary" "$_cnh_managed_fingerprint" || return $?;;
        compatible) ;;
        *) echo 'invalid managed helper qualification policy' >&2; return 2;;
    esac
    _cnh_managed_helper=$(compat_network_helper_local_for_binary "$_cnh_managed_binary") || return $?
    compat_network_helper_validate_managed_signatures "$_cnh_managed_binary" "$_cnh_managed_helper"
}

compat_network_helper_code_digest() {
    _cnh_code_digest=$(/usr/bin/codesign -dv --verbose=4 "$1" 2>&1 | /usr/bin/sed -n 's/^CandidateCDHashFull sha256=//p') || return $?
    compat_network_helper_validate_sha256 "$_cnh_code_digest" || return $?
    printf '%s\n' "$_cnh_code_digest"
}

compat_network_helper_validate_managed_signatures() {
    _cnh_managed_binary=$1 _cnh_managed_helper=$2
    _cnh_managed_team=$(/usr/bin/codesign -dv --verbose=4 "$_cnh_managed_binary" 2>&1 | /usr/bin/sed -n 's/^TeamIdentifier=//p')
    case "$_cnh_managed_team" in ''|*[!A-Z0-9]*) return 1;; esac
    [ "${#_cnh_managed_team}" -eq 10 ] || return 1
    for _cnh_managed_component in engine network-helper storage-control installed-helper; do
        case "$_cnh_managed_component" in
            engine) _cnh_managed_path=$_cnh_managed_binary; _cnh_managed_id=dev.cengine.engine.test-compat;;
            network-helper) _cnh_managed_path=$_cnh_managed_helper; _cnh_managed_id=dev.cengine.network-helper.test-compat;;
            storage-control) _cnh_managed_path="$(dirname "$_cnh_managed_binary")/cengine-storage-controller"; _cnh_managed_id=dev.cengine.storage-control.test-compat;;
            installed-helper) _cnh_managed_path=$compat_network_helper_path; _cnh_managed_id=dev.cengine.network-helper.test-compat;;
        esac
        /usr/bin/codesign --verify --strict -R "=anchor apple generic and identifier \"$_cnh_managed_id\" and certificate leaf[subject.OU] = \"$_cnh_managed_team\"" "$_cnh_managed_path" || return $?
        _cnh_managed_details=$(/usr/bin/codesign -dv --verbose=4 "$_cnh_managed_path" 2>&1) || return $?
        printf '%s\n' "$_cnh_managed_details" | /usr/bin/grep -q '^Authority=Developer ID Application:' || return 1
        printf '%s\n' "$_cnh_managed_details" | /usr/bin/grep -q 'flags=.*runtime' || return 1
    done
}

compat_network_helper_require() {
    _cnh_binary=$1
    _cnh_local_fingerprint=${2:-}
    if [ -n "$_cnh_local_fingerprint" ]; then
        compat_network_helper_validate_fingerprint "$_cnh_local_fingerprint" || return $?
    fi
    [ -x "$_cnh_binary" ] || {
        echo "compatibility cengine binary is missing: $_cnh_binary" >&2
        return 1
    }
    compat_network_helper_validate_installation || {
        _cnh_status=$?
        compat_network_helper_print_install_instruction
        return "$_cnh_status"
    }

    _cnh_selection=$(compat_network_helper_select_policy) || return $?
    _cnh_pair_policy=${_cnh_selection%% *}
    _cnh_requirement=${_cnh_selection#* }
    case "$_cnh_pair_policy:$_cnh_requirement" in
        compatible:lifecycle-v2|exact:lifecycle-v2|exact:lifecycle-qualification) ;;
        *) echo 'invalid helper policy result' >&2; return 2;;
    esac
    if [ "$_cnh_requirement" != none ]; then
        compat_network_helper_validate_fingerprint "$_cnh_local_fingerprint" || return $?
        compat_network_helper_require_managed "$_cnh_binary" "$_cnh_local_fingerprint" "$_cnh_pair_policy" || return $?
        set -- helper status --require-managed "$_cnh_requirement"
    else
        if [ "$_cnh_pair_policy" = exact ]; then
            compat_network_helper_require_exact "$_cnh_binary" "$_cnh_local_fingerprint" || return $?
        fi
        set -- helper status
    fi
    echo "Privileged Helper policy: $_cnh_pair_policy; required contract: $_cnh_requirement" >&2
    _cnh_installed_fingerprint=$(compat_network_helper_installed_fingerprint)
    compat_network_helper_export_environment "$_cnh_installed_fingerprint"
    _cnh_status=$("$_cnh_binary" "$@") || {
        _cnh_status_code=$?
        echo "compatibility Privileged Helper did not pass its authenticated health check" >&2
        compat_network_helper_print_install_instruction
        return "$_cnh_status_code"
    }
    /usr/bin/python3 -c '
import json, sys
value = json.loads(sys.argv[1])
expected_fingerprint, expected_service, expected_owner, expected_protocol, requirement = sys.argv[2:]
assert value["buildFingerprint"] == expected_fingerprint
assert value["serviceName"] == expected_service
assert value["ownerUID"] == int(expected_owner)
assert value["protocolVersion"] == int(expected_protocol)
if requirement != "none":
    # The signed client has already authenticated the ROOT reply and checked the
    # compiled capability/security policy. Do not duplicate that policy in shell.
    assert type(value.get("capabilities")) is dict
    print("Privileged Helper capabilities: " + json.dumps(value["capabilities"], sort_keys=True), file=sys.stderr)
' "$_cnh_status" "$_cnh_installed_fingerprint" "$compat_network_helper_service_name" \
        "$(id -u)" "$compat_network_helper_protocol_version" "$_cnh_requirement" || {
        echo "compatibility Privileged Helper reported unexpected identity or protocol: $_cnh_status" >&2
        compat_network_helper_print_install_instruction
        return 1
    }

    if [ -n "$_cnh_local_fingerprint" ] && \
       [ "$_cnh_local_fingerprint" != "$_cnh_installed_fingerprint" ]; then
        echo "note: compatible provisioned helper differs from the local build; tests are using the provisioned helper" >&2
        echo "      run 'make test-compat-helper-install' only when local helper changes must be exercised" >&2
    fi
}

compat_network_helper_provision() {
    _cnh_helper=$1
    _cnh_binary=$2
    _cnh_fingerprint=$3
    compat_network_helper_validate_fingerprint "$_cnh_fingerprint" || return $?
    [ -x "$_cnh_helper" ] || {
        echo "freshly built compatibility Privileged Helper is missing: $_cnh_helper" >&2
        return 1
    }
    /usr/bin/codesign --verify --strict "$_cnh_helper" >/dev/null
    /usr/bin/codesign --verify --strict "$_cnh_binary" >/dev/null

    if compat_network_helper_matches_local_build "$_cnh_helper" "$_cnh_fingerprint"; then
        if compat_network_helper_require "$_cnh_binary" "$_cnh_fingerprint"; then
            echo "compatibility Privileged Helper already matches the local build" >&2
            return 0
        fi
        echo "reinstalling the matching local helper because its health check failed" >&2
    fi
    compat_network_helper_install \
        "$_cnh_helper" "$_cnh_fingerprint" || return $?
    compat_network_helper_require "$_cnh_binary" "$_cnh_fingerprint"
}

compat_network_helper_uninstall() {
    echo "removing compatibility Privileged Helper $compat_network_helper_label" >&2
    compat_network_helper_run_as_administrator '
set -eu
root=$1
plist=$2
label=$3
/bin/launchctl bootout "system/$label" >/dev/null 2>&1 || true
/bin/rm -f "$plist"
/bin/rm -rf "$root"
' "$compat_network_helper_root" "$compat_network_helper_plist" \
        "$compat_network_helper_label"
}
