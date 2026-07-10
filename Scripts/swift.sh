#!/bin/sh
set -eu

if [ -f /usr/local/include/zlib.h ]; then
  sdk=$(xcrun --sdk macosx --show-sdk-path)
  mkdir -p .build
  sed "s#@SDK@#$sdk#g" Scripts/zlib-vfs.yaml.in > .build/cengine-vfs.yaml
  exec xcrun swift "$@" -Xcc -ivfsoverlay -Xcc .build/cengine-vfs.yaml
fi

exec xcrun swift "$@"
