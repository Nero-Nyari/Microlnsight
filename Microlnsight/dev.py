"""Shared Windows development entry point; uses only the Python standard library."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
PROBE = """
import importlib.util, json, sys
modules = ['fastapi', 'uvicorn', 'sqlalchemy', 'pydantic', 'httpx']
print(json.dumps({'supported': sys.version_info >= (3, 10),
                  'missing': [m for m in modules if importlib.util.find_spec(m) is None]}))
"""


def select_python(explicit=None):
    candidates = [explicit] if explicit else [
        BACKEND / ".venv" / "Scripts" / "python.exe",
        BACKEND / "myenv" / "Scripts" / "python.exe",
        BACKEND / "mayenv" / "Scripts" / "python.exe",
        sys.executable, shutil.which("python"),
    ]
    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).resolve()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            result = subprocess.run([str(path), "-c", PROBE], capture_output=True,
                                    text=True, timeout=20)
            info = json.loads(result.stdout) if result.returncode == 0 else {}
            if info.get("supported") and not info.get("missing", ["probe failed"]):
                print(f"Backend Python: {path}", flush=True)
                return str(path)
            print(f"Skipping {path}: Python 3.10+ and core dependencies required.", flush=True)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            print(f"Skipping unavailable Python: {path}", flush=True)
    raise RuntimeError("No usable Python. See README: create backend/.venv and install requirements.txt.")


def frontend_runtime():
    node = shutil.which("node")
    vite = FRONTEND / "node_modules" / "vite" / "bin" / "vite.js"
    if not node or not vite.is_file():
        raise RuntimeError("Node.js and frontend dependencies required. Run npm ci in frontend.")
    version = subprocess.check_output([node, "--version"], text=True).strip()
    if int(version.lstrip("v").split(".")[0]) < 18:
        raise RuntimeError("Node.js 18+ required.")
    print(f"Frontend Node: {node} ({version})", flush=True)
    return node, str(vite)


def check_backend(python):
    # Import routes without entering the lifespan or opening the user's database.
    env = {**os.environ, "DATABASE_URL": "sqlite:///:memory:", "PYTHONUTF8": "1"}
    result = subprocess.run([python, "-X", "utf8", "-c", "from app.main import app; print('Backend imports OK')"],
                            cwd=BACKEND, env=env)
    if result.returncode:
        raise RuntimeError("Backend imports failed. Install requirements.txt with the Python shown above.")


def wait_ready(url, process, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Service exited before ready: {url}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Service did not become ready: {url}")


def stop_process(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
    else:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def stop_requested():
    # Q also works in Windows terminal hosts that deliver Ctrl+C as input.
    if os.name == 'nt' and sys.stdin.isatty():
        import msvcrt
        return msvcrt.kbhit() and msvcrt.getwch().lower() in ('q', '\x03')
    return False


def start(python, node, vite):
    for port in (8000, 5173):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError as exc:
                raise RuntimeError(f"Port {port} is in use. Stop the existing service before starting.") from exc
    children = []
    try:
        # No reloader: the launcher owns the backend process and can stop it reliably.
        children.append(subprocess.Popen([python, "-X", "utf8", "-m", "uvicorn", "app.main:app",
                                          "--host", "127.0.0.1", "--port", "8000"], cwd=BACKEND, stdin=subprocess.DEVNULL))
        wait_ready("http://127.0.0.1:8000/api/health", children[0])
        children.append(subprocess.Popen([node, vite, "--host", "127.0.0.1", "--port", "5173", "--strictPort"], cwd=FRONTEND, stdin=subprocess.DEVNULL))
        wait_ready("http://127.0.0.1:5173", children[1])
        print("Ready: http://127.0.0.1:5173   |   Q or Ctrl+C stops both services.", flush=True)
        while all(child.poll() is None for child in children):
            if stop_requested():
                return
            time.sleep(0.5)
        raise RuntimeError("A service stopped; shutting down this launcher's remaining service.")
    finally:
        for child in reversed(children):
            try:
                stop_process(child)
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"Could not stop child PID {child.pid}: {exc}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "test", "start", "cli"], nargs="?", default="start")
    parser.add_argument("--python", help="Use this exact backend Python executable (no fallback)")
    args = parser.parse_args()
    try:
        python = select_python(args.python)
        if args.command == "test":
            return subprocess.call([python, "-X", "utf8", "-m", "unittest", "discover", "-s", "tests", "-v"],
                                   cwd=BACKEND, env={**os.environ, "MICROLNSIGHT_TEST_MODE": "1",
                                                     "DATABASE_URL": "sqlite:///:memory:"})
        check_backend(python)
        if args.command == "cli":
            return subprocess.call([python, "-X", "utf8", str(ROOT / "cli.py")], cwd=ROOT)
        node, vite = frontend_runtime()
        if args.command == "check":
            print("Environment checks passed. No services started.")
            return 0
        start(python, node, vite)
    except KeyboardInterrupt:
        print("Stopped.")
        return 0
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
