#!/bin/sh
# Builds toolgate from this checkout and installs it as a service.
#
#   ./scripts/install.sh            isolated install (asks for sudo): own system
#                                   user, data the agents can't read  [recommended]
#   ./scripts/install.sh --user     runs as you, no root needed
#
# Any other flags are passed to `toolgate install` (see -h). Re-run to
# upgrade. Remove with: sudo toolgate uninstall   (or without sudo for --user)
set -eu
cd "$(dirname "$0")/.."
GO=${GO:-$(command -v go || echo "$HOME/sdk/go/bin/go")}
[ -x "$GO" ] || command -v "$GO" >/dev/null || { echo "Go not found; install Go (1.21+) or set GO=/path/to/go"; exit 1; }
mkdir -p bin
"$GO" build -trimpath -ldflags="-s -w" -o bin/toolgate .
case " $* " in
  *" --user "*) exec ./bin/toolgate install "$@" ;;
  *) [ "$(id -u)" -eq 0 ] && exec ./bin/toolgate install "$@"
     exec sudo ./bin/toolgate install "$@" ;;
esac
