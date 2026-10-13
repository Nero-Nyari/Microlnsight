#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -X utf8 "$SCRIPT_DIR/launch_cli.py" "$@"
