"""Install only the dependencies for the current native CLI edition."""
from pathlib import Path
import subprocess
import sys
import venv

from agent import native_platform
from cli_update import atomic, recover, runtime_lock

ROOT = Path(__file__).resolve().parent


def install():
    if sys.version_info < (3, 10):
        raise RuntimeError('Python 3.10+ is required')
    system = native_platform()
    root = ROOT
    environment = root / '.venv-cli'
    venv.EnvBuilder(with_pip=True).create(environment)
    executable = environment / ('Scripts/python.exe' if system == 'windows' else 'bin/python')
    subprocess.run([str(executable), '-m', 'pip', 'install', '-r', str(root / f'requirements-{system}.txt')], check=True)
    atomic(root / 'runtime.json', b'{"environment":".venv-cli"}')
    print(f'Installed {system} CLI. Start: {executable} -X utf8 {root / "agent.py"}')


def main():
    with runtime_lock(ROOT):
        recover(ROOT)
        install()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print(f'Installation failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
