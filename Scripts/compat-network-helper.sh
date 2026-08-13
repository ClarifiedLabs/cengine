#!/bin/sh
# Persistent compatibility-test networking helper lifecycle.
# Source this file from compatibility runners; do not execute it directly.

compat_network_helper_service_name="dev.cengine.network-helper.test-compat"
compat_network_helper_label="dev.cengine.network-helper.test-compat"
compat_network_helper_protocol_version=5
compat_network_helper_support_root="/Library/Application Support/cengine"
compat_network_helper_parent="$compat_network_helper_support_root/compat"
compat_network_helper_root="/Library/Application Support/cengine/compat/dev.cengine.network-helper.test-compat"
compat_network_helper_path="$compat_network_helper_root/cengine-network-helper"
compat_network_helper_token_path="$compat_network_helper_root/client-token"
compat_network_helper_manifest_path="$compat_network_helper_root/manifest"
compat_network_helper_plist="/Library/LaunchDaemons/dev.cengine.network-helper.test-compat.plist"

compat_network_helper_local_for_binary() {
    _cnh_binary_dir=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd) || return 1
    printf '%s/cengine-network-helper\n' "$_cnh_binary_dir"
}

compat_network_helper_validate_fingerprint() {
    case "$1" in
        ""|*[!0123456789abcdef]*)
            echo "invalid compatibility networking helper fingerprint: $1" >&2
            return 2
            ;;
    esac
    [ "${#1}" -eq 64 ] || {
        echo "compatibility networking helper fingerprint must contain 64 hexadecimal characters" >&2
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
            echo "invalid compatibility networking helper SHA-256: $1" >&2
            return 2
            ;;
    esac
    [ "${#1}" -eq 64 ] || {
        echo "compatibility networking helper SHA-256 must contain 64 hexadecimal characters" >&2
        return 2
    }
}

compat_network_helper_validate_root_controlled() {
    _cnh_controlled_path=$1
    [ ! -L "$_cnh_controlled_path" ] || {
        echo "compatibility networking helper path must not be a symbolic link: $_cnh_controlled_path" >&2
        return 1
    }
    _cnh_controlled_owner=$(/usr/bin/stat -f '%u' "$_cnh_controlled_path") || return 1
    [ "$_cnh_controlled_owner" = 0 ] || {
        echo "compatibility networking helper path is not owned by root: $_cnh_controlled_path" >&2
        return 1
    }
    _cnh_controlled_permissions=$(/usr/bin/stat -f '%Sp' "$_cnh_controlled_path") || return 1
    case "$_cnh_controlled_permissions" in
        ?????w????*|????????w?*)
            echo "compatibility networking helper path is group- or world-writable: $_cnh_controlled_path" >&2
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
            echo "compatibility networking helper directory is missing: $_cnh_controlled_path" >&2
            return 1
        }
    done
    [ -x "$compat_network_helper_path" ] || {
        echo "compatibility networking helper executable is missing: $compat_network_helper_path" >&2
        return 1
    }
    [ -r "$compat_network_helper_token_path" ] || {
        echo "compatibility networking helper token is missing or unreadable: $compat_network_helper_token_path" >&2
        return 1
    }
    [ -f "$compat_network_helper_manifest_path" ] || {
        echo "compatibility networking helper manifest is missing: $compat_network_helper_manifest_path" >&2
        return 1
    }
    [ -f "$compat_network_helper_plist" ] || {
        echo "compatibility networking helper plist is missing: $compat_network_helper_plist" >&2
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
        echo "compatibility networking helper has an invalid code signature" >&2
        return 1
    }

    _cnh_installed_owner=$(compat_network_helper_installed_owner 2>/dev/null || true)
    [ "$_cnh_installed_owner" = "$_cnh_expected_owner" ] || {
        echo "compatibility networking helper is provisioned for UID ${_cnh_installed_owner:-missing}, not $_cnh_expected_owner" >&2
        return 1
    }
    _cnh_installed_fingerprint=$(compat_network_helper_installed_fingerprint 2>/dev/null || true)
    compat_network_helper_validate_fingerprint "$_cnh_installed_fingerprint" || return $?
    _cnh_installed_sha=$(compat_network_helper_installed_sha256 2>/dev/null || true)
    compat_network_helper_validate_sha256 "$_cnh_installed_sha" || return $?
    _cnh_actual_sha=$(/usr/bin/shasum -a 256 "$compat_network_helper_path" | /usr/bin/awk '{ print $1 }')
    [ "$_cnh_installed_sha" = "$_cnh_actual_sha" ] || {
        echo "compatibility networking helper does not match its installed manifest" >&2
        return 1
    }

    [ ! -L "$compat_network_helper_token_path" ] || {
        echo "compatibility networking helper token must not be a symbolic link" >&2
        return 1
    }
    _cnh_token_owner=$(/usr/bin/stat -f '%u' "$compat_network_helper_token_path") || return 1
    _cnh_token_mode=$(/usr/bin/stat -f '%Lp' "$compat_network_helper_token_path") || return 1
    [ "$_cnh_token_owner" = "$_cnh_expected_owner" ] || {
        echo "compatibility networking helper token is not owned by UID $_cnh_expected_owner" >&2
        return 1
    }
    [ "$_cnh_token_mode" = 600 ] || {
        echo "compatibility networking helper token mode is $_cnh_token_mode, expected 600" >&2
        return 1
    }

    /bin/launchctl print "system/$compat_network_helper_label" >/dev/null 2>&1 || {
        echo "compatibility networking helper LaunchDaemon is not loaded" >&2
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

    echo "installing compatibility networking helper $compat_network_helper_label" >&2
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
rollback() {
    status=$?
    trap - 0 1 2 15
    if [ "$installed" -eq 0 ]; then
        /bin/launchctl bootout "system/$label" >/dev/null 2>&1 || true
        /bin/rm -rf "$root"
        /bin/rm -f "$plist_target"
        if [ "$had_root" -eq 1 ]; then /bin/mv "$backup_root" "$root"; fi
        if [ "$had_plist" -eq 1 ]; then /bin/mv "$backup_plist" "$plist_target"; fi
        if [ "$had_plist" -eq 1 ]; then
            /bin/launchctl bootstrap system "$plist_target" >/dev/null 2>&1 || true
        fi
    fi
    /bin/rm -rf "$backup_root"
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
for backup in "$backup_root" "$backup_plist"; do
    if [ -e "$backup" ] || [ -L "$backup" ]; then
        echo "refusing to overwrite stale helper backup: $backup" >&2
        exit 1
    fi
done
trap rollback 0
trap "exit 1" 1 2 15
/bin/launchctl bootout "system/$label" >/dev/null 2>&1 || true
if [ -e "$root" ] || [ -L "$root" ]; then /bin/mv "$root" "$backup_root"; had_root=1; fi
if [ -e "$plist_target" ] || [ -L "$plist_target" ]; then
    /bin/mv "$plist_target" "$backup_plist"
    had_plist=1
fi
/bin/mkdir "$root"
/bin/mkdir -p "$log_dir"
/usr/bin/ditto --norsrc --noextattr "$helper" "$target"
/bin/cp "$token_source" "$token_target"
/bin/cp "$manifest_source" "$manifest_target"
/bin/cp "$plist_source" "$plist_target"
/usr/sbin/chown -R root:wheel "$root"
/usr/sbin/chown "$owner_uid" "$token_target"
/bin/chmod 755 "$root" "$target"
/bin/chmod 600 "$token_target"
/bin/chmod 644 "$manifest_target" "$plist_target"
/usr/bin/codesign --verify --strict "$target"
/usr/bin/plutil -lint "$plist_target" >/dev/null
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

    _cnh_installed_fingerprint=$(compat_network_helper_installed_fingerprint)
    compat_network_helper_export_environment "$_cnh_installed_fingerprint"
    _cnh_status=$("$_cnh_binary" network-helper status) || {
        _cnh_status_code=$?
        echo "compatibility networking helper did not pass its authenticated health check" >&2
        compat_network_helper_print_install_instruction
        return "$_cnh_status_code"
    }
    /usr/bin/python3 -c '
import json, sys
value = json.loads(sys.argv[1])
expected_fingerprint, expected_service, expected_owner, expected_protocol = sys.argv[2:]
assert value["buildFingerprint"] == expected_fingerprint
assert value["serviceName"] == expected_service
assert value["ownerUID"] == int(expected_owner)
assert value["protocolVersion"] == int(expected_protocol)
' "$_cnh_status" "$_cnh_installed_fingerprint" "$compat_network_helper_service_name" \
        "$(id -u)" "$compat_network_helper_protocol_version" || {
        echo "compatibility networking helper reported unexpected identity or protocol: $_cnh_status" >&2
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
        echo "freshly built compatibility networking helper is missing: $_cnh_helper" >&2
        return 1
    }
    /usr/bin/codesign --verify --strict "$_cnh_helper" >/dev/null
    /usr/bin/codesign --verify --strict "$_cnh_binary" >/dev/null

    if compat_network_helper_matches_local_build "$_cnh_helper" "$_cnh_fingerprint"; then
        if compat_network_helper_require "$_cnh_binary" "$_cnh_fingerprint"; then
            echo "compatibility networking helper already matches the local build" >&2
            return 0
        fi
        echo "reinstalling the matching local helper because its health check failed" >&2
    fi
    compat_network_helper_install \
        "$_cnh_helper" "$_cnh_fingerprint" || return $?
    compat_network_helper_require "$_cnh_binary" "$_cnh_fingerprint"
}

compat_network_helper_uninstall() {
    echo "removing compatibility networking helper $compat_network_helper_label" >&2
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
