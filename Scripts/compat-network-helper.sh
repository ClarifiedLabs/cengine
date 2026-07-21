#!/bin/sh
# Persistent compatibility-test networking helper lifecycle.
# Source this file from compatibility runners; do not execute it directly.

compat_network_helper_service_name="dev.cengine.network-helper.test-compat"
compat_network_helper_label="dev.cengine.network-helper.test-compat"
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

compat_network_helper_run_as_administrator() {
    _cnh_script=$1
    shift
    /usr/bin/osascript - "$_cnh_script" "$@" <<'APPLESCRIPT'
on run argv
    if (count of argv) < 1 then error "missing administrator session command"
    set shellCommand to "/bin/sh -c " & quoted form of (item 1 of argv) & " cengine-compat-helper"
    if (count of argv) > 1 then
        repeat with argumentIndex from 2 to count of argv
            set shellCommand to shellCommand & " " & quoted form of (item argumentIndex of argv)
        end repeat
    end if
    do shell script shellCommand with administrator privileges
end run
APPLESCRIPT
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

compat_network_helper_is_current() {
    _cnh_expected=$1
    _cnh_local_helper=${2:-}
    _cnh_installed=$(compat_network_helper_installed_fingerprint 2>/dev/null || true)
    _cnh_owner=$(compat_network_helper_installed_owner 2>/dev/null || true)
    [ "$_cnh_installed" = "$_cnh_expected" ] || return 1
    [ "$_cnh_owner" = "$(id -u)" ] || return 1
    [ -x "$compat_network_helper_path" ] || return 1
    [ -r "$compat_network_helper_token_path" ] || return 1
    /usr/bin/codesign --verify --strict "$compat_network_helper_path" >/dev/null 2>&1 || return 1
    if [ -n "$_cnh_local_helper" ]; then
        _cnh_installed_sha=$(compat_network_helper_installed_sha256 2>/dev/null || true)
        _cnh_local_sha=$(/usr/bin/shasum -a 256 "$_cnh_local_helper" | /usr/bin/awk '{ print $1 }')
        [ "$_cnh_installed_sha" = "$_cnh_local_sha" ] || return 1
    fi
    /bin/launchctl print "system/$compat_network_helper_label" >/dev/null 2>&1
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
    _cnh_binary=$3
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
binary=${12}
fingerprint=${13}
service=${14}
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
trap rollback 0
trap "exit 1" 1 2 15
/bin/launchctl bootout "system/$label" >/dev/null 2>&1 || true
if [ -e "$root" ]; then /bin/mv "$root" "$backup_root"; had_root=1; fi
if [ -e "$plist_target" ]; then /bin/mv "$plist_target" "$backup_plist"; had_plist=1; fi
/bin/mkdir -p "$root" "$log_dir"
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
/usr/bin/codesign --verify --strict "$binary"
/usr/bin/plutil -lint "$plist_target" >/dev/null
/bin/launchctl bootstrap system "$plist_target"
/bin/launchctl kickstart "system/$label"
/bin/sleep 1
/bin/launchctl print "system/$label" >/dev/null
health=$(/usr/bin/env \
    CENGINE_NETWORK_HELPER_SERVICE_NAME="$service" \
    CENGINE_NETWORK_HELPER_IDENTIFIER=dev.cengine.network-helper.test-compat \
    CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE="$token_target" \
    "$binary" network-helper status)
/usr/bin/python3 -c "import json,sys; value=json.loads(sys.argv[1]); \
assert value.get(\"buildFingerprint\") == sys.argv[2]; \
assert value.get(\"serviceName\") == sys.argv[3]; \
assert value.get(\"ownerUID\") == int(sys.argv[4])" \
    "$health" "$fingerprint" "$service" "$owner_uid"
installed=1
' "$compat_network_helper_root" "$_cnh_helper" "$compat_network_helper_path" \
        "$_cnh_temp_token" "$compat_network_helper_token_path" \
        "$_cnh_temp_manifest" "$compat_network_helper_manifest_path" \
        "$_cnh_temp_plist" "$compat_network_helper_plist" \
        "$compat_network_helper_label" "$_cnh_owner_uid" "$_cnh_binary" \
        "$_cnh_fingerprint" "$compat_network_helper_service_name"; then
        _cnh_status=0
    else
        _cnh_status=$?
    fi
    /bin/rm -rf "$_cnh_temporary"
    return "$_cnh_status"
}

compat_network_helper_ensure() {
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

    if ! compat_network_helper_is_current "$_cnh_fingerprint" "$_cnh_helper"; then
        compat_network_helper_install \
            "$_cnh_helper" "$_cnh_fingerprint" "$_cnh_binary" || return $?
    fi
    compat_network_helper_export_environment "$_cnh_fingerprint"

    _cnh_status=$("$_cnh_binary" network-helper status) || {
        echo "compatibility networking helper did not pass its authenticated health check" >&2
        return 1
    }
    /usr/bin/python3 -c '
import json, sys
value = json.loads(sys.argv[1])
expected_fingerprint, expected_service, expected_owner = sys.argv[2:]
assert value["buildFingerprint"] == expected_fingerprint
assert value["serviceName"] == expected_service
assert value["ownerUID"] == int(expected_owner)
' "$_cnh_status" "$_cnh_fingerprint" "$compat_network_helper_service_name" "$(id -u)" || {
        echo "compatibility networking helper reported unexpected identity: $_cnh_status" >&2
        return 1
    }
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
