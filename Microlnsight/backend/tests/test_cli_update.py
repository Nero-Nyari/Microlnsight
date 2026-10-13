"""Update transactions against local fixture releases, never live GitHub."""
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
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import cli_update as update
from build_cli_releases import build


def package(files, system):
    files = dict(files)
    files['SHA256SUMS.txt'] = ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n'
                                     for name, data in sorted(files.items()) if name != 'SHA256SUMS.txt').encode()
    buffer = io.BytesIO()
    prefix = f'winsecagent-{system}-cli/'
    if system == 'windows':
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(prefix + name, data)
    else:
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(prefix + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class UpdateTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict('os.environ', {'WINSEC_UPDATE_TOKEN': ''})
        environment.start()
        self.addCleanup(environment.stop)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'backend/data')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'installed'
        self.system = platform.system().lower()
        artifacts = build(self.base / 'release', '0.2.0')
        archive = next(path for path in artifacts if f'-{self.system}-' in path.name)
        self.old = update.unpack(archive.read_bytes(), self.system, '0.2.0')
        for name, data in self.old.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.data = self.root / 'data/agent.guard/tasks.db'
        self.data.parent.mkdir(parents=True)
        self.data.write_bytes(b'private task data')
        self.config = self.root / 'data/agent.guard/models.json'
        self.config.write_bytes(b'private model settings')
        self.env = self.root / '.env'
        self.env.write_bytes(b'private env data')
        self.new = dict(self.old)
        self.new['edition.json'] = json.dumps({**json.loads(self.old['edition.json']), 'version': '0.2.1'}).encode()
        self.new['agent.py'] += b'\n# Fixture release update\n'
        self.configure_download()

    def configure_download(self):
        self.archive = package(self.new, self.system)
        self.info = dict(available=True, latest='0.2.1', filename='release', asset_url='asset', checksums_url='checksums')
        self.responses = {'asset': self.archive,
                          'checksums': (hashlib.sha256(self.archive).hexdigest() + '  release\n').encode()}

    def perform(self):
        with patch('cli_update.download', side_effect=lambda url, *args: self.responses[url]), \
                patch('cli_update.runtime_python', return_value=Path(sys.executable)):
            return update.apply(self.root, self.info, progress=lambda _: None)

    def assert_private_unchanged(self):
        self.assertEqual(self.data.read_bytes(), b'private task data')
        self.assertEqual(self.config.read_bytes(), b'private model settings')
        self.assertEqual(self.env.read_bytes(), b'private env data')

    def test_update_runs_real_isolated_demo_and_preserves_private_data(self):
        self.assertTrue(self.perform())
        self.assertEqual(update.installed(self.root)['version'], '0.2.1')
        self.assertTrue((self.root / 'agent.py').read_bytes().endswith(b'# Fixture release update\n'))
        self.assertFalse((self.root / '.update-transaction.json').exists())
        self.assert_private_unchanged()

    def test_download_corruption_does_not_touch_existing_files(self):
        self.responses['asset'] += b'tampered'
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.perform()
        self.assertEqual((self.root / 'edition.json').read_bytes(), self.old['edition.json'])
        self.assert_private_unchanged()

    def test_modified_local_code_is_preserved(self):
        local = self.root / 'agent.py'
        local.write_bytes(b'# local change')
        with self.assertRaisesRegex(ValueError, '本机程序文件被修改'):
            self.perform()
        self.assertEqual(local.read_bytes(), b'# local change')

    def test_failed_smoke_keeps_old_program(self):
        with patch('cli_update.smoke', side_effect=RuntimeError('fixture smoke failure')):
            with self.assertRaisesRegex(RuntimeError, 'smoke failure'):
                self.perform()
        self.assertEqual((self.root / 'edition.json').read_bytes(), self.old['edition.json'])
        self.assertFalse((self.root / '.update-transaction.json').exists())
        self.assert_private_unchanged()

    def test_partial_replacement_failure_restores_old_program(self):
        atomic = update.atomic
        failed = False

        def fail_once(path, data):
            nonlocal failed
            if Path(path) == self.root / 'guard.py' and not failed:
                failed = True
                raise OSError('fixture disk write failure')
            return atomic(path, data)

        with patch('cli_update.atomic', side_effect=fail_once), patch('cli_update.smoke'):
            with self.assertRaisesRegex(OSError, 'disk write'):
                self.perform()
        for name, data in self.old.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        self.assertFalse((self.root / '.update-transaction.json').exists())
        self.assert_private_unchanged()

    def test_crash_journal_recovers_on_next_start(self):
        transaction = 'a' * 32
        backup = self.root / '.updates' / transaction / 'backup'
        backup.mkdir(parents=True)
        (backup / 'agent.py').write_bytes(self.old['agent.py'])
        (self.root / 'agent.py').write_bytes(b'# interrupted new program')
        (self.root / 'new_module.py').write_bytes(b'# newly added')
        (self.root / '.update-transaction.json').write_text(json.dumps(dict(id=transaction,
            files={'agent.py': True, 'new_module.py': False})))
        self.assertTrue(update.recover(self.root))
        self.assertEqual((self.root / 'agent.py').read_bytes(), self.old['agent.py'])
        self.assertFalse((self.root / 'new_module.py').exists())
        self.assertFalse(update.recover(self.root))

    def test_dependency_change_uses_separate_environment_and_switches_only_on_success(self):
        self.new[f'requirements-{self.system}.txt'] += b'\n# fixture dependency revision\n'
        self.configure_download()
        with patch('cli_update.subprocess.run') as run, patch('cli_update.smoke'):
            self.assertTrue(self.perform())
        self.assertEqual(run.call_count, 2)
        self.assertIn('venv', run.call_args_list[0].args[0])
        relative = json.loads((self.root / 'runtime.json').read_bytes())['environment']
        self.assertTrue(relative.startswith('.updates/env-'))
        self.assert_private_unchanged()

    def test_dependency_failure_keeps_old_version_and_runtime(self):
        self.new[f'requirements-{self.system}.txt'] += b'\n# fixture revision\n'
        self.configure_download()
        with patch('cli_update.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'pip')):
            with self.assertRaisesRegex(RuntimeError, '依赖准备失败'):
                self.perform()
        self.assertFalse((self.root / 'runtime.json').exists())
        self.assertEqual((self.root / 'edition.json').read_bytes(), self.old['edition.json'])

    def test_archive_rejects_wrong_platform_paths_and_private_data(self):
        for name in ('../escape.py', '/absolute.py', 'backend/app/../../data/key.py',
                     'data/settings.py', 'runtime.json', 'C:/escape.py'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                update.unpack(package({**self.new, name: b'bad'}, self.system), self.system, '0.2.1')
        with self.assertRaisesRegex(ValueError, '版本'):
            update.unpack(self.archive, self.system, '9.0.0')

    def test_check_distinguishes_unpublished_old_and_new_releases(self):
        def release(tag):
            filename = f'winsecagent-{self.system}-cli' + ('.zip' if self.system == 'windows' else '.tar.gz')
            return dict(tag_name=tag, assets=[dict(name=name, browser_download_url=
                f'https://github.com/{update.REPOSITORY}/releases/download/{tag}/{name}')
                for name in (filename, 'SHA256SUMS.txt')])
        with patch('cli_update.download', return_value=b'[]'):
            result = update.check(self.root)
            self.assertFalse(result['available'])
            self.assertIn('尚无', result['message'])
        with patch('cli_update.download', return_value=json.dumps([release('cli-v0.2.1'),
                {**release('cli-v9.0.0'), 'prerelease': True}]).encode()):
            self.assertTrue(update.check(self.root)['available'])
        with patch('cli_update.download', return_value=json.dumps([release('cli-v0.1.0')]).encode()):
            self.assertFalse(update.check(self.root)['available'])

    def test_runtime_lock_rejects_second_instance(self):
        with update.runtime_lock(self.root):
            with self.assertRaisesRegex(RuntimeError, '进程运行'):
                with update.runtime_lock(self.root):
                    pass

    def test_private_asset_urls_and_redirect_do_not_leak_token(self):
        filename = f'winsecagent-{self.system}-cli' + ('.zip' if self.system == 'windows' else '.tar.gz')
        release = dict(tag_name='cli-v0.2.1', assets=[dict(name=name,
            url=f'https://api.github.com/repos/{update.REPOSITORY}/releases/assets/{i}',
            browser_download_url=f'https://github.com/{update.REPOSITORY}/releases/download/cli-v0.2.1/{name}')
            for i, name in enumerate((filename, 'SHA256SUMS.txt'), 1)])
        with patch.dict('os.environ', {'WINSEC_UPDATE_TOKEN': 'secret-test-token'}), \
                patch('cli_update.download', return_value=json.dumps([release]).encode()):
            info = update.check(self.root)
            self.assertTrue(info['asset_url'].startswith('https://api.github.com/'))
            self.assertNotIn('secret-test-token', str(info))
        request = urllib.request.Request('https://api.github.com/releases/assets/1', headers={'Authorization': 'Bearer secret'})
        redirected = update.SafeRedirect().redirect_request(request, None, 302, 'found', {}, 'https://release-assets.githubusercontent.com/test')
        self.assertIsNone(redirected.get_header('Authorization'))
        with self.assertRaises(ValueError):
            update.SafeRedirect().redirect_request(request, None, 302, 'found', {}, 'http://example.com/test')


if __name__ == '__main__':
    unittest.main()
