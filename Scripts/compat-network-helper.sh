#!/bin/sh
# Shared compatibility-test networking-helper selection and local bootstrap support.
# Source this file from compatibility runners; do not execute it directly.

compat_network_helper_installed_path="/Applications/cengine.app/Contents/MacOS/cengine-network-helper"
compat_network_helper_default_service_name="dev.cengine.network-helper"
compat_network_helper_test_compat_service_name="dev.cengine.network-helper.test-compat"

compat_network_helper_absolute_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$(pwd)" "$1" ;;
    esac
}

compat_network_helper_local_for_binary() {
    _cnh_binary_dir=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd) || return 1
    printf '%s/cengine-network-helper\n' "$_cnh_binary_dir"
}

compat_network_helper_for_binary() {
    _cnh_binary=$1
    _cnh_mode=${CENGINE_COMPAT_NETWORK_HELPER:-auto}
    case "$_cnh_mode" in
        auto|installed|local) ;;
        *)
            echo "unsupported CENGINE_COMPAT_NETWORK_HELPER=$_cnh_mode; expected auto, installed, or local" >&2
            return 2
            ;;
    esac

    if [ -n "${CENGINE_NETWORK_HELPER_PATH:-}" ]; then
        _cnh_helper=$(compat_network_helper_absolute_path "$CENGINE_NETWORK_HELPER_PATH")
        if [ ! -x "$_cnh_helper" ]; then
            echo "configured cengine networking helper is missing: $_cnh_helper" >&2
            return 1
        fi
        printf '%s\n' "$_cnh_helper"
        return 0
    fi

    _cnh_local_helper=$(compat_network_helper_local_for_binary "$_cnh_binary") || return 1
    case "$_cnh_mode" in
        installed)
            _cnh_helper=$compat_network_helper_installed_path
            ;;
        local)
            _cnh_helper=$_cnh_local_helper
            ;;
        auto)
            if [ -x "$_cnh_local_helper" ]; then
                _cnh_helper=$_cnh_local_helper
            else
                _cnh_helper=$compat_network_helper_installed_path
            fi
            ;;
    esac

    if [ -x "$_cnh_helper" ]; then
        printf '%s\n' "$_cnh_helper"
        return 0
    fi

    case "$_cnh_mode" in
        installed)
            echo "installed cengine networking helper is missing: $_cnh_helper" >&2
            echo "install the current cengine package or set CENGINE_COMPAT_NETWORK_HELPER=local" >&2
            ;;
        local)
            echo "local cengine networking helper is missing: $_cnh_helper" >&2
            echo "run make build before running compatibility tests" >&2
            ;;
        auto)
            echo "cengine networking helper is missing" >&2
            echo "checked installed helper: $compat_network_helper_installed_path" >&2
            echo "checked local build helper: $_cnh_local_helper" >&2
            echo "run make build or install the current cengine package before running compatibility tests" >&2
            ;;
    esac
    return 1
}

compat_network_helper_is_installed() {
    [ "$1" = "$compat_network_helper_installed_path" ]
}

compat_network_helper_label() {
    printf '%s\n' "$compat_network_helper_test_compat_service_name"
}

compat_network_helper_dynamic_label() {
    _cnh_seed=${CENGINE_COMPAT_HELPER_LABEL_SEED:-${ROOT:-$(pwd)}}
    _cnh_hash=$(printf '%s' "$_cnh_seed" | shasum -a 256 | awk '{ print substr($1, 1, 12) }')
    printf 'dev.cengine.network-helper.compat.%s.%s\n' "$(id -u)" "$_cnh_hash"
}

compat_network_helper_validate_label() {
    case "$1" in
        ""|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-]*)
            echo "invalid compatibility networking helper label: $1" >&2
            return 2
            ;;
    esac
}

compat_network_helper_run_as_administrator() {
    _cnh_script=$1
    _cnh_log=$2
    shift 2
    /usr/bin/osascript - "$_cnh_script" "$_cnh_log" "$@" <<'APPLESCRIPT'
on run argv
    set argumentCount to count of argv
    if argumentCount < 2 then error "missing administrator session command"
    set shellCommand to "/bin/mkdir -p /Library/Logs/cengine && (/bin/sh -c " & quoted form of (item 1 of argv) & " cengine-compat-helper"
    if argumentCount > 2 then
        repeat with argumentIndex from 3 to argumentCount
            set shellCommand to shellCommand & " " & quoted form of (item argumentIndex of argv)
        end repeat
    end if
    set shellCommand to shellCommand & " </dev/null > " & quoted form of (item 2 of argv) & " 2>&1 &)"
    do shell script shellCommand with administrator privileges
end run
APPLESCRIPT
}

compat_network_helper_bootstrap_local() {
    _cnh_helper=$1
    _cnh_service=${2:-$(compat_network_helper_label)}
    _cnh_export_client_service=${3:-0}
    compat_network_helper_validate_label "$_cnh_service" || return $?
    _cnh_label=${CENGINE_COMPAT_NETWORK_HELPER_LABEL:-$_cnh_service}
    compat_network_helper_validate_label "$_cnh_label" || return $?
    _cnh_staging_root="/Library/Application Support/cengine/compat/$_cnh_label"
    _cnh_staged_helper="$_cnh_staging_root/cengine-network-helper"
    _cnh_plist="/Library/LaunchDaemons/$_cnh_label.plist"
    _cnh_log_dir="/Library/Logs/cengine"
    _cnh_stdout="$_cnh_log_dir/$_cnh_label.out.log"
    _cnh_stderr="$_cnh_log_dir/$_cnh_label.err.log"
    _cnh_temp_plist=$(mktemp -t cengine-network-helper) || return 1

    if ! codesign --verify --strict "$_cnh_helper" >/dev/null 2>&1; then
        rm -f "$_cnh_temp_plist"
        echo "local cengine networking helper is not signed: $_cnh_helper" >&2
        return 1
    fi

    cat > "$_cnh_temp_plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>$_cnh_label</string>
    <key>ProgramArguments</key><array><string>$_cnh_staged_helper</string></array>
    <key>MachServices</key><dict><key>$_cnh_service</key><true/></dict>
    <key>EnvironmentVariables</key><dict>
        <key>CENGINE_NETWORK_HELPER_SERVICE_NAME</key><string>$_cnh_service</string>
    </dict>
    <key>ProcessType</key><string>Interactive</string>
    <key>StandardOutPath</key><string>$_cnh_stdout</string>
    <key>StandardErrorPath</key><string>$_cnh_stderr</string>
</dict></plist>
EOF

    _cnh_client_uid=$(id -u)
    _cnh_session_token=$(/usr/bin/uuidgen | /usr/bin/tr -d '-')
    _cnh_control_root="/var/run/cengine-compat/$_cnh_client_uid-$_cnh_session_token"
    _cnh_admin_log="$_cnh_log_dir/$_cnh_label.admin.log"
    _cnh_owner_pid=$$

    echo "bootstrapping local cengine networking helper: $_cnh_label" >&2
    _cnh_status=0
    compat_network_helper_run_as_administrator '
set -eu
staging_root=$1
log_dir=$2
helper=$3
staged_helper=$4
temp_plist=$5
plist=$6
label=$7
client_uid=$8
session_token=$9
owner_pid=${10}
admin_log=${11}
case "$client_uid" in ""|*[!0123456789]*) exit 2 ;; esac
case "$session_token" in ""|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789]*) exit 2 ;; esac
control_base=/var/run/cengine-compat
control_root="$control_base/$client_uid-$session_token"
request_root="$control_root/requests"
status_root="$control_root/status"
control_created=0
cleanup() {
    status=$?
    trap - 0 1 2 15
    /bin/launchctl bootout "system/$label" >/dev/null 2>&1 || true
    /bin/rm -f "$plist"
    /bin/rm -rf "$staging_root"
    if [ "$control_created" = 1 ]; then /bin/rm -rf "$control_root"; fi
    /bin/rmdir "$control_base" >/dev/null 2>&1 || true
    if [ "$status" -eq 0 ]; then /bin/rm -f "$admin_log"; fi
    exit "$status"
}
trap cleanup 0
trap "exit 1" 1 2 15
/bin/mkdir -p "$control_base"
/usr/sbin/chown root:wheel "$control_base"
/bin/chmod 755 "$control_base"
/bin/mkdir "$control_root"
control_created=1
/bin/mkdir "$request_root" "$status_root"
/usr/sbin/chown "$client_uid" "$request_root"
/bin/chmod 700 "$request_root"
/bin/chmod 755 "$status_root"
if [ -e "$request_root/stop" ]; then exit 0; fi
/bin/mkdir -p "$staging_root" "$log_dir"
/usr/bin/ditto --norsrc --noextattr "$helper" "$staged_helper"
/usr/sbin/chown root:wheel "$staged_helper"
/bin/chmod 755 "$staged_helper"
/usr/bin/codesign --verify --strict "$staged_helper"
/bin/cp "$temp_plist" "$plist"
/usr/sbin/chown root:wheel "$plist"
/bin/chmod 644 "$plist"
if [ -e "$request_root/stop" ]; then exit 0; fi
/bin/launchctl bootout "system/$label" >/dev/null 2>&1 || true
/bin/launchctl bootstrap system "$plist"
: > "$status_root/ready"
/bin/chmod 644 "$status_root/ready"
while /bin/kill -0 "$owner_pid" >/dev/null 2>&1; do
    if [ -e "$request_root/stop" ]; then exit 0; fi
    for request in "$request_root"/restart-*; do
        [ -f "$request" ] || continue
        request_name=${request##*/}
        request_id=${request_name#restart-}
        /bin/rm -f "$request"
        case "$request_id" in ""|*[!0123456789abcdef]*) continue ;; esac
        output="$status_root/restart-$request_id.output"
        response="$status_root/restart-$request_id.status"
        output_temp="$output.$$"
        response_temp="$response.$$"
        if (
            helper_pid() {
                /bin/launchctl print "system/$label" 2>/dev/null \
                    | /usr/bin/awk "\$1 == \"pid\" && \$2 == \"=\" { print \$3; exit }"
            }
            old_pid=$(helper_pid)
            if [ -z "$old_pid" ]; then
                echo "compatibility networking helper is not running"
                exit 1
            fi
            /bin/launchctl kill SIGTERM "system/$label"
            attempt=0
            while [ "$(helper_pid)" = "$old_pid" ]; do
                attempt=$((attempt + 1))
                if [ "$attempt" -ge 300 ]; then
                    echo "timed out waiting for compatibility networking helper $old_pid to stop"
                    exit 1
                fi
                /bin/sleep 0.1
            done
            /bin/launchctl kickstart "system/$label"
            attempt=0
            new_pid=$(helper_pid)
            while [ -z "$new_pid" ] || [ "$new_pid" = "$old_pid" ]; do
                attempt=$((attempt + 1))
                if [ "$attempt" -ge 300 ]; then
                    echo "timed out waiting for compatibility networking helper to restart"
                    exit 1
                fi
                /bin/sleep 0.1
                new_pid=$(helper_pid)
            done
            echo "restarted compatibility networking helper $old_pid as $new_pid"
        ) > "$output_temp" 2>&1; then
            restart_status=0
        else
            restart_status=$?
        fi
        /usr/bin/printf "%s\n" "$restart_status" > "$response_temp"
        /bin/chmod 644 "$output_temp" "$response_temp"
        /bin/mv "$output_temp" "$output"
        /bin/mv "$response_temp" "$response"
        break
    done
    /bin/sleep 0.1
done
' "$_cnh_admin_log" "$_cnh_staging_root" "$_cnh_log_dir" "$_cnh_helper" \
        "$_cnh_staged_helper" "$_cnh_temp_plist" "$_cnh_plist" "$_cnh_label" \
        "$_cnh_client_uid" "$_cnh_session_token" "$_cnh_owner_pid" "$_cnh_admin_log" \
        || _cnh_status=$?
    if [ "$_cnh_status" -ne 0 ]; then
        rm -f "$_cnh_temp_plist"
        return "$_cnh_status"
    fi

    CENGINE_COMPAT_NETWORK_HELPER_CONTROL_ROOT=$_cnh_control_root
    CENGINE_COMPAT_NETWORK_HELPER_ADMIN_LOG=$_cnh_admin_log
    export CENGINE_COMPAT_NETWORK_HELPER_CONTROL_ROOT
    export CENGINE_COMPAT_NETWORK_HELPER_ADMIN_LOG

    _cnh_attempt=0
    while [ ! -f "$_cnh_control_root/status/ready" ]; do
        _cnh_attempt=$((_cnh_attempt + 1))
        if [ "$_cnh_attempt" -ge 300 ]; then
            [ ! -f "$_cnh_admin_log" ] || cat "$_cnh_admin_log" >&2
            rm -f "$_cnh_temp_plist"
            unset CENGINE_COMPAT_NETWORK_HELPER_CONTROL_ROOT
            unset CENGINE_COMPAT_NETWORK_HELPER_ADMIN_LOG
            echo "timed out starting privileged compatibility networking helper session" >&2
            return 1
        fi
        sleep 0.1
    done
    rm -f "$_cnh_temp_plist"

    if [ "$_cnh_export_client_service" = "1" ]; then
        CENGINE_NETWORK_HELPER_SERVICE_NAME=$_cnh_service
        export CENGINE_NETWORK_HELPER_SERVICE_NAME
    fi
    CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_LABEL=$_cnh_label
    CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_PLIST=$_cnh_plist
    CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_ROOT=$_cnh_staging_root
    export CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_LABEL
    export CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_PLIST
    export CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_ROOT
}

compat_network_helper_cleanup_local() {
    _cnh_control_root=${CENGINE_COMPAT_NETWORK_HELPER_CONTROL_ROOT:-}
    _cnh_admin_log=${CENGINE_COMPAT_NETWORK_HELPER_ADMIN_LOG:-}
    [ -n "$_cnh_control_root" ] || return 0

    _cnh_label=${CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_LABEL:-compatibility helper}
    echo "removing local cengine networking helper: $_cnh_label" >&2
    _cnh_status=0
    if [ -d "$_cnh_control_root/requests" ]; then
        : > "$_cnh_control_root/requests/stop"
        _cnh_attempt=0
        while [ -e "$_cnh_control_root" ]; do
            _cnh_attempt=$((_cnh_attempt + 1))
            if [ "$_cnh_attempt" -ge 300 ]; then
                echo "timed out stopping privileged compatibility networking helper session" >&2
                _cnh_status=1
                break
            fi
            sleep 0.1
        done
    else
        _cnh_status=1
    fi
    if [ "$_cnh_status" -ne 0 ] && [ -f "$_cnh_admin_log" ]; then
        cat "$_cnh_admin_log" >&2
    fi
    unset CENGINE_NETWORK_HELPER_SERVICE_NAME
    unset CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_LABEL
    unset CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_PLIST
    unset CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_ROOT
    unset CENGINE_COMPAT_NETWORK_HELPER_CONTROL_ROOT
    unset CENGINE_COMPAT_NETWORK_HELPER_ADMIN_LOG
    return "$_cnh_status"
}
