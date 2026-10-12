"""Select the active virtual environment and recover interrupted updates."""
from pathlib import Path
import subprocess
import sys

from cli_update import recover, runtime_lock, runtime_python


def main():
    root = Path(__file__).resolve().parent
    with runtime_lock(root):
        if recover(root):
            print('上次更新中断，已恢复旧版。')
        python = runtime_python(root)
        if not python.is_file():
            raise RuntimeError('请先运行本平台的安装脚本')
    return subprocess.call([str(python), '-X', 'utf8', str(root / 'agent.py'), *sys.argv[1:]])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError) as exc:
        print(f'启动失败：{exc}', file=sys.stderr)
        raise SystemExit(1)
