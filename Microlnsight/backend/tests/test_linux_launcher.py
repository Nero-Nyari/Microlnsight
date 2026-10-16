"""Exercise the shell entry point with controlled old/new interpreter stubs."""
from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SHELL = shutil.which('bash') or ('C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else None)


@unittest.skipUnless(SHELL and Path(SHELL).is_file(), 'POSIX shell unavailable')
class LinuxLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='launcher test ', dir=ROOT / 'backend/data')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.script(self.bin / 'dirname', '#!/bin/sh\nif [ "$1" = "--" ]; then shift; fi\nprintf "%s\\n" "${1%/*}"\n')
        for name in ('python3', 'python3.10', 'python3.11', 'python3.12', 'python3.13', 'python3.14'):
            self.script(self.bin / name, '#!/bin/sh\nexit 1\n')
        (self.root / 'start-linux.sh').write_bytes((ROOT / 'start-linux.sh').read_bytes().replace(b'\r\n', b'\n'))

    def script(self, path, source):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding='utf-8', newline='\n')
        path.chmod(0o755)

    def modern(self, path):
        self.script(path, '#!/bin/sh\nif [ "$1" = "-c" ]; then exit 0; fi\nprintf "%s\\n" "$@"\n')

    def run_launcher(self):
        # Set PATH inside the shell so Windows drive-letter separators are not interpreted as PATH entries.
        command = 'export PATH="$(cd "$1" && pwd)"; exec /bin/sh "$2" scan --minutes 60 "argument with spaces"'
        return subprocess.run([SHELL, '-c', command, 'test', self.bin.as_posix(),
                               (self.root / 'start-linux.sh').as_posix()],
                              capture_output=True, encoding='utf-8', timeout=15)

    def test_installed_environment_precedes_old_system_python_and_preserves_args(self):
        self.modern(self.root / '.venv-cli/bin/python')
        result = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('launch_cli.py', result.stdout)
        self.assertEqual(result.stdout.splitlines()[-4:], ['scan', '--minutes', '60', 'argument with spaces'])

    def test_versioned_python_is_used_when_default_is_too_old(self):
        self.modern(self.bin / 'python3.11')
        result = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('launch_cli.py', result.stdout)

    def test_no_supported_interpreter_reports_actionable_error(self):
        result = self.run_launcher()
        self.assertEqual(result.returncode, 1)
        self.assertIn('Python 3.10+', result.stderr)
        self.assertNotIn('Traceback', result.stderr)


class LauncherVersionTests(unittest.TestCase):
    def test_direct_old_python_launch_fails_before_updater_import(self):
        with patch.object(sys, 'version_info', (3, 6, 8)), redirect_stderr(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(ROOT / 'launch_cli.py'), run_name='launcher_version_test')
        self.assertEqual(caught.exception.code, 1)
        self.assertIn('Python 3.10+', output.getvalue())


if __name__ == '__main__':
    unittest.main()
