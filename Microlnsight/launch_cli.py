"""Select the active virtual environment and recover interrupted updates."""
from pathlib import Path
import os
import subprocess
import sys

if sys.version_info < (3, 10):
    print('启动失败：需要 Python 3.10+，请使用安装环境的 Python 或 start-linux.sh。', file=sys.stderr)
    raise SystemExit(1)

from cli_update import recover, runtime_lock, runtime_python


def main():
    root = Path(__file__).resolve().parent
    with runtime_lock(root):
        if recover(root):
            print('上次更新中断，已恢复旧版。')
        python = runtime_python(root)
        if not python.is_file():
            raise RuntimeError('请先运行本平台的安装脚本')
    command = [str(python), '-X', 'utf8', str(root / 'agent.py'), *sys.argv[1:]]
    if sys.platform.startswith('linux'):
        # Let the CLI own terminal signals and finish saving on Ctrl+C.
        # A waiting wrapper can raise KeyboardInterrupt and kill its child.
        os.execv(str(python), command)
    return subprocess.call(command)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError) as exc:
        print(f'启动失败：{exc}', file=sys.stderr)
        raise SystemExit(1)
