#!/bin/sh
# Kept for existing setups: same as `sudo bin/toolgate install --isolated`
# with the binary already built in bin/. Old flags still work:
#   --user NAME  (desktop user whose per-user install is cleaned up) -> --owner
#   --from DIR   migrate a `migrate-export` directory
#   --keep-old   no-op (old data is only deleted with --remove-old-data)
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
n=$#
while [ "$n" -gt 0 ]; do
  case "$1" in
    --user) set -- "$@" --owner "$2"; shift 2; n=$((n - 2)) ;;
    --keep-old) shift; n=$((n - 1)) ;;
    *) set -- "$@" "$1"; shift; n=$((n - 1)) ;;
  esac
done
exec "$HERE/bin/toolgate" install --isolated "$@"
