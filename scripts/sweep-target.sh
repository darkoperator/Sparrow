#!/usr/bin/env bash
# Opt-in sweep of stale build output in a cargo target directory. Never run automatically.
#
#   scripts/sweep-target.sh [--days N] [--dry-run] [--force] [TARGET_DIR]
#
# * In every <profile>/deps directory (target/debug/deps, target/release/deps,
#   target/<triple>/debug/deps, ...) keeps only the NEWEST artifact per crate name and kind
#   (executable, .d, .rlib, .rmeta, .dylib, .dSYM, ...): `name-<16 hex>` files from older builds
#   are removed. Anything removed that a later build still needs is simply rebuilt.
# * Removes entries of every <profile>/incremental directory older than N days (default 3).
# * Skips anything modified in the last hour (a build may be running) unless --force.
# TARGET_DIR defaults to ./target.
set -euo pipefail

days=3
dry=0
force=0
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --days) days="$2"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --force) force=1; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) target="$1"; shift ;;
  esac
done
target="${target:-target}"
[ -d "$target" ] || { echo "sweep-target: $target is not a directory" >&2; exit 1; }

mtime() { # seconds since the epoch, portable between BSD and GNU stat
  stat -f %m "$1" 2>/dev/null || stat -c %Y "$1"
}
now=$(date +%s)
freed=0
size_kb() { du -sk "$1" 2>/dev/null | cut -f1; }
remove() {
  local kb
  kb=$(size_kb "$1")
  freed=$((freed + ${kb:-0}))
  if [ "$dry" = 1 ]; then echo "would remove $1"; else rm -rf -- "$1"; fi
}

# deps: one newest artifact per (crate name, kind)
while IFS= read -r deps; do
  tmp=$(mktemp)
  for f in "$deps"/*; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    if [[ "$base" =~ ^(.+)-([0-9a-f]{16})(\..*)?$ ]]; then
      printf '%s\t%s\t%s\n' "${BASH_REMATCH[1]}${BASH_REMATCH[3]:-}" "$(mtime "$f")" "$f" >> "$tmp"
    fi
  done
  # newest first within each key; every later entry of the same key is stale
  while IFS=$'\t' read -r t f; do
    if [ "$force" = 0 ] && [ $((now - t)) -lt 3600 ]; then continue; fi
    remove "$f"
  done < <(sort -t$'\t' -k1,1 -k2,2nr "$tmp" | awk -F'\t' '
    $1 == prev { print $2 "\t" $3; next }
    { prev = $1 }')
  rm -f "$tmp"
done < <(find "$target" -maxdepth 4 -type d -name deps)

# incremental: entries older than N days
while IFS= read -r inc; do
  while IFS= read -r e; do
    [ "$force" = 0 ] && [ $((now - $(mtime "$e"))) -lt 3600 ] && continue
    remove "$e"
  done < <(find "$inc" -mindepth 1 -maxdepth 1 -mtime +"$days")
done < <(find "$target" -maxdepth 4 -type d -name incremental)

echo "sweep-target: $([ "$dry" = 1 ] && echo 'would free' || echo 'freed') about $((freed / 1024)) MB in $target"
