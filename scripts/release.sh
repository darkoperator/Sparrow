#!/usr/bin/env bash
# Release builds of the CLI and the review app, from any directory.
#
#   scripts/release.sh [--cli] [--app]
#
# * --cli   cargo build --release -p sparrow-cli          -> target/release/sparrow
# * --app   tauri build (front end built into app/dist)   -> target/release/sparrow-app, and a bundle on the platforms
#           that ask for one (tauri.conf.json leaves bundling off): on macOS target/release/bundle/macos/Sparrow.app,
#           on Windows the installer target/release/bundle/nsis/Sparrow_<version>_<arch>-setup.exe
# Windows runs this from Git Bash, and its binaries end in .exe. The first Windows bundle downloads the NSIS tools.
# Neither flag builds both. Front-end packages are installed from app/package-lock.json first when app/node_modules
# is missing (`npm ci`; set NPM_OFFLINE=1 for `npm ci --offline`). CARGO_TARGET_DIR is honoured.
set -euo pipefail

cli=0
app=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cli) cli=1; shift ;;
    --app) app=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "release: unknown argument $1 (try --help)" >&2; exit 2 ;;
  esac
done
if [ $cli -eq 0 ] && [ $app -eq 0 ]; then cli=1; app=1; fi

root="$(cd "$(dirname "$0")/.." && pwd)"
target="${CARGO_TARGET_DIR:-$root/target}"
os="$(uname -s)"
exe=""
case "$os" in MINGW*|MSYS*|CYGWIN*) exe=".exe" ;; esac

case "$target" in
  /*) ;;
  # A drive path, which is absolute only on Windows; elsewhere C:/build is a relative folder like any other.
  [A-Za-z]:[\\/]*) if [ -z "$exe" ]; then target="$root/$target"; fi ;;
  *) target="$root/$target" ;;
esac

if [ $cli -eq 1 ]; then
  echo "release: building the CLI"
  (cd "$root" && cargo build --release -p sparrow-cli)
  echo "release: CLI at $target/release/sparrow$exe"
fi

if [ $app -eq 1 ]; then
  if [ ! -d "$root/app/node_modules" ]; then
    echo "release: installing front-end packages from the lockfile"
    if [ "${NPM_OFFLINE:-0}" = "1" ]; then npm --prefix "$root/app" ci --offline; else npm --prefix "$root/app" ci; fi
  fi
  echo "release: building the review app"
  # tauri.conf.json's beforeBuildCommand builds the front end into app/dist; run from the root, where the CLI finds it.
  bundles=()
  if [ "$os" = "Darwin" ]; then bundles=(--bundles app); fi
  if [ -n "$exe" ]; then bundles=(--bundles nsis); fi
  (cd "$root" && "$root/app/node_modules/.bin/tauri" build "${bundles[@]+"${bundles[@]}"}")
  echo "release: app binary at $target/release/sparrow-app$exe"
  if [ -d "$target/release/bundle" ]; then
    find "$target/release/bundle" -mindepth 2 -maxdepth 2 \( -name '*.app' -o -name '*-setup.exe' \) -print \
      | sed 's/^/release: bundle at /'
  fi
fi
