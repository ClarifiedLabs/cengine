#!/bin/sh
set -eu

plugin=${1:?Docker plugin name is required}
ambient_docker_config=${2:-${DOCKER_CONFIG:-${HOME:-}/.docker}}

print_absolute() {
    candidate=$1
    candidate_directory=$(CDPATH= cd -- "$(dirname -- "$candidate")" && pwd)
    printf '%s/%s\n' "$candidate_directory" "$(basename -- "$candidate")"
}

if candidate=$(command -v "docker-$plugin" 2>/dev/null) \
    && [ -f "$candidate" ] && [ -x "$candidate" ]; then
    print_absolute "$candidate"
    exit 0
fi

for plugin_directory in \
    "$ambient_docker_config/cli-plugins" \
    "${HOME:-}/.docker/cli-plugins" \
    "/Applications/Docker.app/Contents/Resources/cli-plugins" \
    "/opt/homebrew/lib/docker/cli-plugins" \
    "/usr/local/lib/docker/cli-plugins"
do
    candidate="$plugin_directory/docker-$plugin"
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
        print_absolute "$candidate"
        exit 0
    fi
done

exit 1
