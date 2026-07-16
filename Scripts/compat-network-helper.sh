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

    echo "bootstrapping local cengine networking helper: $_cnh_label" >&2
    /usr/bin/sudo /bin/mkdir -p "$_cnh_staging_root" "$_cnh_log_dir"
    /usr/bin/sudo /usr/bin/ditto --norsrc --noextattr "$_cnh_helper" "$_cnh_staged_helper"
    /usr/bin/sudo /usr/sbin/chown root:wheel "$_cnh_staged_helper"
    /usr/bin/sudo /bin/chmod 755 "$_cnh_staged_helper"
    /usr/bin/sudo /usr/bin/codesign --verify --strict "$_cnh_staged_helper"
    /usr/bin/sudo /bin/cp "$_cnh_temp_plist" "$_cnh_plist"
    /usr/bin/sudo /usr/sbin/chown root:wheel "$_cnh_plist"
    /usr/bin/sudo /bin/chmod 644 "$_cnh_plist"
    /usr/bin/sudo /bin/launchctl bootout "system/$_cnh_label" >/dev/null 2>&1 || true
    /usr/bin/sudo /bin/launchctl bootstrap system "$_cnh_plist"
    rm -f "$_cnh_temp_plist"
}

compat_network_helper_cleanup_local() {
    _cnh_label=${CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_LABEL:-}
    [ -n "$_cnh_label" ] || return 0
    _cnh_plist=${CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_PLIST:-/Library/LaunchDaemons/$_cnh_label.plist}
    _cnh_root=${CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_ROOT:-/Library/Application Support/cengine/compat/$_cnh_label}

    echo "removing local cengine networking helper: $_cnh_label" >&2
    /usr/bin/sudo /bin/launchctl bootout "system/$_cnh_label" >/dev/null 2>&1 || true
    /usr/bin/sudo /bin/rm -f "$_cnh_plist"
    /usr/bin/sudo /bin/rm -rf "$_cnh_root"
    unset CENGINE_NETWORK_HELPER_SERVICE_NAME
    unset CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_LABEL
    unset CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_PLIST
    unset CENGINE_COMPAT_BOOTSTRAPPED_NETWORK_HELPER_ROOT
}
