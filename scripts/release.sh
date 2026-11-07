#!/usr/bin/env bash
# Release builds of the CLI and the review app, from any directory.
#
#   scripts/release.sh [--cli] [--app] [--package]
#
# * --cli   cargo build --release -p sparrow-cli          -> target/release/sparrow
# * --app   tauri build (front end built into app/dist)   -> target/release/sparrow-app, and a bundle on the platforms
#           that ask for one (tauri.conf.json leaves bundling off): on macOS target/release/bundle/macos/Sparrow.app,
#           on Windows the installer target/release/bundle/nsis/Sparrow_<version>_<arch>-setup.exe
# * --package  builds both, then puts what a GitHub release uploads in target/release/dist, with its checksums: the app
#           and the CLI together, because they refuse to talk across versions. It refuses a working tree with changes
#           to the build inputs (crates/, app/, Cargo.*): a release is the commit, not whatever else sits in the folder.
#           Build from a git worktree at the release commit; RELEASE_ALLOW_DIRTY=1 overrides.
# Windows runs this from Git Bash, and its binaries end in .exe. The first Windows bundle downloads the NSIS tools.
# Windows release builds link the C runtime statically, so they run on a machine without the Visual C++ redistributable.
# Neither flag builds both. Front-end packages are installed from app/package-lock.json first when app/node_modules
# is missing (`npm ci`; set NPM_OFFLINE=1 for `npm ci --offline`). CARGO_TARGET_DIR is honoured.
set -euo pipefail

cli=0
app=0
package=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cli) cli=1; shift ;;
    --app) app=1; shift ;;
    --package) package=1; cli=1; app=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "release: unknown argument $1 (try --help)" >&2; exit 2 ;;
  esac
done
if [ $cli -eq 0 ] && [ $app -eq 0 ]; then cli=1; app=1; fi

root="$(cd "$(dirname "$0")/.." && pwd)"
target="${CARGO_TARGET_DIR:-$root/target}"
os="$(uname -s)"
exe=""
case "$os" in MINGW*|MSYS*|CYGWIN*) exe=".exe" ;; esac

if [ -n "$exe" ]; then export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static"; fi

case "$target" in
  /*) ;;
  # A drive path, which is absolute only on Windows; elsewhere C:/build is a relative folder like any other.
  [A-Za-z]:[\\/]*) if [ -z "$exe" ]; then target="$root/$target"; fi ;;
  *) target="$root/$target" ;;
esac

if [ $package -eq 1 ] && git -C "$root" rev-parse --git-dir >/dev/null 2>&1; then
  # Editor swap files are not build inputs; anything else changed or untracked would ship unreviewed.
  dirty="$(git -C "$root" status --porcelain --untracked-files=all -- crates app Cargo.toml Cargo.lock \
    | grep -Ev '\.sw[a-p]$' || true)"
  if [ -n "$dirty" ] && [ "${RELEASE_ALLOW_DIRTY:-0}" != "1" ]; then
    echo "release: refusing to package: the working tree has changes not in commit $(git -C "$root" rev-parse --short HEAD):" >&2
    echo "$dirty" | head -20 | sed 's/^/release:   /' >&2
    echo "release: build from a worktree at the release commit (git worktree add ../Sparrow-rel <commit>)," >&2
    echo "release: or set RELEASE_ALLOW_DIRTY=1 to package them anyway" >&2
    exit 1
  fi
  echo "release: packaging commit $(git -C "$root" rev-parse --short HEAD)${dirty:+ (dirty, allowed)}"
fi

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

if [ $package -eq 1 ]; then
  version="$("$target/release/sparrow$exe" --version | awk '{print $2}')"
  case "$(uname -m)" in
    x86_64) arch=x64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) arch="$(uname -m)" ;;
  esac
  dist="$target/release/dist"
  rm -rf "$dist"
  mkdir -p "$dist"
  bundle="$target/release/bundle"
  stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' EXIT
  cp "$target/release/sparrow$exe" "$root/LICENSE" "$stage/"
  if [ -n "$exe" ]; then
    # The bundle folder keeps installers from earlier versions; take this version's alone.
    cp "$bundle/nsis/Sparrow_${version}_${arch}-setup.exe" "$dist/"
    powershell.exe -NoProfile -Command "Compress-Archive -Path '$(cygpath -w "$stage")\*' -DestinationPath '$(cygpath -w "$dist")\sparrow-cli-$version-windows-$arch.zip'"
  elif [ "$os" = "Darwin" ]; then
    ditto -c -k --keepParent "$bundle/macos/Sparrow.app" "$dist/Sparrow-$version-macos-$arch.zip"
    tar -czf "$dist/sparrow-cli-$version-macos-$arch.tar.gz" -C "$stage" .
  else
    tar -czf "$dist/sparrow-cli-$version-linux-$arch.tar.gz" -C "$stage" .
    cp "$target/release/sparrow-app" "$stage/"
    tar -czf "$dist/sparrow-app-$version-linux-$arch.tar.gz" -C "$stage" sparrow-app LICENSE
  fi
  if command -v sha256sum >/dev/null; then sum=(sha256sum); else sum=(shasum -a 256); fi
  # Named per platform: the release holds one of these from each machine that built it.
  case "$os" in MINGW*|MSYS*|CYGWIN*) platform=windows ;; Darwin) platform=macos ;; *) platform=linux ;; esac
  sums="$stage/sums"
  (cd "$dist" && "${sum[@]}" -- * > "$sums")
  mv "$sums" "$dist/SHA256SUMS-$platform-$arch.txt"
  echo "release: upload these from $dist:"
  ls -1 "$dist" | sed 's/^/release:   /'
fi
