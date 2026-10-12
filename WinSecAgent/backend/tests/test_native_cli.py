"""Native installers, local-only routing, and isolated release smoke tests."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import agent
import build_cli_releases
import guard
import install_cli


class NativeCliTests(unittest.TestCase):
    def test_both_native_platforms_route_scan_without_ssh(self):
        for system in ('Windows', 'Linux'):
            with self.subTest(system=system), tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as directory:
                collector = 'collect_windows' if system == 'Windows' else 'collect_linux'
                with patch('agent.platform.system', return_value=system), \
                        patch('guard_cli.' + collector, return_value=guard.demo_events(system.lower())) as read, \
                        redirect_stdout(io.StringIO()):
                    self.assertEqual(agent.main(['--data-dir', directory, 'scan']), 0)
                if system == 'Linux':
                    read.assert_called_once_with(None, 15, 1000)
                else:
                    read.assert_called_once_with(1000)
                task = guard.TaskStore(Path(directory) / 'agent.guard/tasks.db').recent()[0]
                self.assertEqual(task['source'], system.lower() + ':local')

    def test_native_menu_is_available_without_legacy_backend_and_has_no_ssh_prompt(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as directory:
            output = io.StringIO()
            with patch('builtins.input', return_value='0'), redirect_stdout(output):
                self.assertEqual(agent.main(['--data-dir', directory]), 0)
            self.assertIn('本机版', output.getvalue())
            self.assertNotIn('SSH 别名', output.getvalue())

    def test_install_selects_platform_dependencies_without_services_or_privilege_changes(self):
        for system, executable in (('windows', 'Scripts/python.exe'), ('linux', 'bin/python')):
            with patch('install_cli.native_platform', return_value=system), \
                    patch('install_cli.venv.EnvBuilder') as builder, \
                    patch('install_cli.atomic'), \
                    patch('install_cli.subprocess.run') as run, redirect_stdout(io.StringIO()):
                install_cli.main()
                builder.return_value.create.assert_called_once_with(ROOT / '.venv-cli')
                self.assertEqual(run.call_args.args[0], [str(ROOT / '.venv-cli' / executable), '-m', 'pip', 'install',
                                                       '-r', str(ROOT / f'requirements-{system}.txt')])

    def test_release_contains_only_allowed_files_and_runs_without_site_packages(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as directory:
            directory = Path(directory)
            archives = build_cli_releases.build(directory / 'release')
            for archive in archives:
                if archive.suffix == '.zip':
                    with zipfile.ZipFile(archive) as bundle:
                        files = {name: bundle.read(name) for name in bundle.namelist()}
                else:
                    with tarfile.open(archive) as bundle:
                        files = {member.name: bundle.extractfile(member).read() for member in bundle.getmembers()}
                for name in files:
                    self.assertFalse(name.endswith(('.db', '.log', '.env')))
                    self.assertNotIn('models.json', name)
                prefix = next(iter(files)).split('/')[0]
                payload = {name[len(prefix) + 1:]: data for name, data in files.items()}
                manifest = json.loads(payload['edition.json'])
                if manifest['platform'] == 'linux':
                    self.assertFalse(any(name.startswith('backend/') for name in payload))
                    self.assertNotIn(b'\r', payload['start-linux.sh'])
                for line in payload['SHA256SUMS.txt'].decode().splitlines():
                    checksum, name = line.split('  ', 1)
                    self.assertEqual(hashlib.sha256(payload[name]).hexdigest(), checksum)
                # Extract our allowlisted files, with an explicit containment check.
                unpacked = (directory / prefix).resolve()
                for name, data in payload.items():
                    destination = (unpacked / name).resolve()
                    self.assertTrue(destination.is_relative_to(unpacked))
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                # Run the edition for the real current OS. CI repeats on Linux.
                if manifest['platform'] == platform.system().lower():
                    result = subprocess.run([sys.executable, '-S', '-X', 'utf8', str(unpacked / 'agent.py'), 'demo'],
                                            cwd=unpacked, capture_output=True, text=True, encoding='utf-8', timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('合成演示数据', result.stdout)
                    self.assertIn('模拟器自检', result.stdout)
                else:
                    with patch('agent.ROOT', unpacked):
                        with self.assertRaisesRegex(ValueError, '安装包'):
                            agent.native_platform()


if __name__ == '__main__':
    unittest.main()
