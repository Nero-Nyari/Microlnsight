#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# The system python3 may be older than the installed CLI environment (e.g. UOS).
# launch_cli still resolves runtime.json and recovers interrupted updates.
for candidate in "$SCRIPT_DIR/.venv-cli/bin/python" python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
        exec "$candidate" -X utf8 "$SCRIPT_DIR/launch_cli.py" "$@"
    fi
done
printf '%s\n' '启动失败：需要 Python 3.10+。未找到可用的安装环境或 Python；请使用 Python 3.10+ 运行 install_cli.py。' >&2
exit 1
