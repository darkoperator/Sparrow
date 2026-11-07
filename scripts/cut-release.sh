#!/usr/bin/env bash
# Cut a release in its own git worktree, so a shared checkout (where other work may be in progress) is never
# switched or packaged.
#
#   scripts/cut-release.sh prepare <version>   worktree ../Sparrow-rel-<version> on branch release/<version> off main;
#                                              sets the version, refreshes both lockfiles, and writes
#                                              docs/releases/v<version>.md from the previous release's notes with a
#                                              TODO in "What's new"
#   scripts/cut-release.sh package <version>   refuses while the notes hold the TODO; commits "release: v<version>"
#                                              if not yet committed, runs scripts/release.sh --package in the worktree
#                                              (sharing this checkout's target folder), smoke-tests the uploads, and
#                                              prints the publish commands
#
# Publishing (merge into main, tag, push, gh release create) is printed, not run: it cannot be taken back.
set -euo pipefail

usage() { sed -n '2,14p' "$0"; exit 2; }
[ $# -eq 2 ] || usage
cmd="$1"
version="$2"
tag="v$version"

main_root="$(cd "$(dirname "$0")/.." && pwd)"
# From inside a worktree, the main checkout is the first entry of `git worktree list`.
main_root="$(git -C "$main_root" worktree list --porcelain | awk 'NR==1{print $2}')"
wt="$(dirname "$main_root")/Sparrow-rel-$version"
notes="docs/releases/$tag.md"
todo="<!-- TODO: what's new -->"

case "$cmd" in
prepare)
  [ -e "$wt" ] && { echo "cut-release: $wt already exists" >&2; exit 1; }
  git -C "$main_root" rev-parse --verify -q "refs/tags/$tag" >/dev/null && { echo "cut-release: tag $tag exists" >&2; exit 1; }
  git -C "$main_root" worktree add -b "release/$version" "$wt" main
  cd "$wt"
  prev="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
  [ -n "$prev" ] || { echo "cut-release: no workspace version in Cargo.toml" >&2; exit 1; }
  sed -i.bak "s/^version = \"$prev\"/version = \"$version\"/" Cargo.toml && rm Cargo.toml.bak
  sed -i.bak "s/\"version\": \"$prev\"/\"version\": \"$version\"/" app/package.json && rm app/package.json.bak
  cargo update --workspace
  npm --prefix app install --package-lock-only
  prev_notes="docs/releases/v$prev.md"
  if [ -f "$prev_notes" ]; then
    # Keep the previous notes' framing, Install, Known limits and Feedback; replace "What's new" with the TODO.
    awk -v todo="$todo" '
      /^## What.s new/ { print; print ""; print todo; print ""; skip=1; next }
      /^## / { skip=0 }
      !skip' "$prev_notes" \
      | sed -e "s/$prev/$version/g" -e "s/the CLI from \`v[^\`]*\`/the CLI from \`v$prev\`/" > "$notes"
  else
    printf '# Sparrow %s\n\n## What%ss new\n\n%s\n' "$tag" "'" "$todo" > "$notes"
  fi
  echo "cut-release: $prev -> $version in $wt"
  echo "cut-release: next, write \"What's new\" in $wt/$notes (and the build ordinal in its first line),"
  echo "cut-release: then run scripts/cut-release.sh package $version"
  ;;
package)
  [ -d "$wt" ] || { echo "cut-release: no worktree at $wt; run prepare first" >&2; exit 1; }
  cd "$wt"
  grep -qF "$todo" "$notes" && { echo "cut-release: $notes still has the What's new TODO" >&2; exit 1; }
  if [ "$(git log -1 --format=%s)" != "release: $tag" ]; then
    git add Cargo.toml Cargo.lock app/package.json app/package-lock.json "$notes"
    git commit -q -m "release: $tag" -m "Set the version to $version."
  fi
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$main_root/target}" scripts/release.sh --package
  dist="${CARGO_TARGET_DIR:-$main_root/target}/release/dist"
  # Smoke test: checksums, the CLI's version, a synthetic ingest, and the app staying up.
  smoke="$(mktemp -d)"
  trap 'rm -rf "$smoke"' EXIT
  (cd "$dist" && shasum -a 256 -c SHA256SUMS-*.txt)
  cli_tgz="$(ls "$dist"/sparrow-cli-"$version"-*.tar.gz)"
  tar -xzf "$cli_tgz" -C "$smoke"
  got="$("$smoke/sparrow" --version | awk '{print $2}')"
  [ "$got" = "$version" ] || { echo "cut-release: packaged CLI says $got, expected $version" >&2; exit 1; }
  "$smoke/sparrow" synth --scenario bec-aitm --collector hawk4 --out "$smoke/tree" >/dev/null
  "$smoke/sparrow" ingest "$smoke/tree" --case "$smoke/case.duckdb" >/dev/null
  if [ "$(uname -s)" = "Darwin" ]; then
    (cd "$smoke" && ditto -x -k "$dist/Sparrow-$version-macos-"*.zip .)
    "$smoke/Sparrow.app/Contents/MacOS/sparrow-app" >/dev/null 2>&1 &
    app=$!
    sleep 6
    kill -0 "$app" 2>/dev/null || { echo "cut-release: the packaged app exited within 6 s" >&2; exit 1; }
    kill "$app"
  fi
  echo "cut-release: smoke test passed (checksums, CLI $version, synthetic ingest, app start)"
  commit="$(git rev-parse --short HEAD)"
  on="$(git -C "$main_root" branch --show-current)"
  cat <<EOF
cut-release: to publish $tag (commit $commit):
  # in a checkout on main (the root checkout is on ${on:-a detached HEAD}; merge there only if that is main):
  git merge --ff-only release/$version     # or a merge commit if main moved on
  git -C "$main_root" tag -a $tag -m "Sparrow $tag" $commit
  git -C "$main_root" push origin main $tag
  gh release create $tag --prerelease --title "Sparrow $tag" --verify-tag \\
    --notes-file "$wt/$notes" "$dist"/*
  git -C "$main_root" worktree remove "$wt" && git -C "$main_root" branch -d release/$version
EOF
  ;;
*) usage ;;
esac
