"""Brand migration contracts, using temporary data and the frozen old updater."""
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'backend'))
import agent
import cli_update
from build_cli_releases import build
from app.core import storage_migration as storage

spec = importlib.util.spec_from_file_location('legacy_updater', Path(__file__).parent / 'fixtures/legacy_cli_update.py')
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


class StorageMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'backend/data')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_wal_records_survive_and_old_database_is_retained(self):
        source = self.root / storage.LEGACY_DATABASE_NAME
        with closing(sqlite3.connect(source)) as old:
            old.execute('PRAGMA journal_mode=WAL')
            old.execute('PRAGMA wal_autocheckpoint=0')
            old.execute('CREATE TABLE evidence (value TEXT)')
            old.execute('INSERT INTO evidence VALUES (?)', ('retained evidence',))
            old.commit()
            self.assertTrue(Path(str(source) + '-wal').exists())
            target = storage.migrate_database(self.root)
            with closing(sqlite3.connect(target)) as migrated:
                self.assertEqual(migrated.execute('SELECT * FROM evidence').fetchall(), [('retained evidence',)])
            self.assertEqual(old.execute('SELECT * FROM evidence').fetchall(), [('retained evidence',)])
        self.assertTrue(source.exists())
        self.assertEqual(storage.default_database(self.root), target)
        self.assertFalse(list(self.root.glob('.microlnsight-migration-*')))

    def test_existing_destination_is_not_overwritten(self):
        target = self.root / storage.DATABASE_NAME
        target.write_bytes(b'existing user data')
        with self.assertRaises(FileExistsError):
            storage.migrate_database(self.root)
        self.assertEqual(target.read_bytes(), b'existing user data')

    def test_old_database_requires_explicit_migration_and_busy_writer_blocks_it(self):
        source = self.root / storage.LEGACY_DATABASE_NAME
        with closing(sqlite3.connect(source)) as old:
            old.execute('CREATE TABLE evidence (value TEXT)')
            old.commit()
            with self.assertRaises(storage.MigrationRequired):
                storage.default_database(self.root)
            old.execute('BEGIN IMMEDIATE')
            with self.assertRaises(sqlite3.OperationalError):
                storage.migrate_database(self.root)
            old.rollback()
        self.assertFalse((self.root / storage.DATABASE_NAME).exists())
        self.assertFalse(list(self.root.glob('.microlnsight-migration-*')))

    def test_invalid_source_leaves_no_new_database(self):
        (self.root / storage.LEGACY_DATABASE_NAME).write_bytes(b'not sqlite')
        with self.assertRaises(sqlite3.DatabaseError):
            storage.migrate_database(self.root)
        self.assertFalse((self.root / storage.DATABASE_NAME).exists())

    def test_fresh_database_and_collection_names_and_collision_guard(self):
        self.assertEqual(storage.default_database(self.root).name, 'microlnsight.db')
        client = Mock()
        client.list_collections.return_value = [storage.LEGACY_COLLECTION_NAME]
        self.assertTrue(storage.migrate_collection(client))
        client.get_collection.return_value.modify.assert_called_once_with(name=storage.COLLECTION_NAME)
        client.reset_mock()
        client.list_collections.return_value = [storage.LEGACY_COLLECTION_NAME, storage.COLLECTION_NAME]
        with self.assertRaises(ValueError):
            storage.migrate_collection(client)
        client.get_collection.assert_not_called()
        client.list_collections.return_value = [storage.COLLECTION_NAME]
        self.assertFalse(storage.migrate_collection(client))


class ConfigurationMigrationTests(unittest.TestCase):
    def test_new_token_has_precedence_and_legacy_token_still_works(self):
        with patch.dict(os.environ, {'WINSEC_UPDATE_TOKEN': 'old'}, clear=True):
            self.assertEqual(cli_update.update_token(), 'old')
            os.environ['MICROLNSIGHT_UPDATE_TOKEN'] = 'new'
            self.assertEqual(cli_update.update_token(), 'new')
            os.environ['MICROLNSIGHT_UPDATE_TOKEN'] = ''
            self.assertEqual(cli_update.update_token(), '')

    def test_data_directory_precedence_retains_legacy_configuration(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as directory:
            old, new = Path(directory) / 'old', Path(directory) / 'new'
            with patch.dict(os.environ, {'WINSEC_DATA_DIR': str(old)}, clear=True), \
                    patch('agent.native_platform', return_value='windows'), patch('guard_cli.dispatch') as dispatch:
                self.assertEqual(agent._main(['scan']), 0)
                self.assertEqual(dispatch.call_args.args[0].database, old / 'agent.db')
                os.environ['MICROLNSIGHT_DATA_DIR'] = str(new)
                self.assertEqual(agent._main(['scan']), 0)
                self.assertEqual(dispatch.call_args.args[0].database, new / 'agent.db')


class ReleaseMigrationTests(unittest.TestCase):
    def test_new_and_bridge_packages_have_identical_payloads_on_both_platforms(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as directory:
            artifacts = build(directory)
            self.assertEqual(len(artifacts), 4)
            for system in ('windows', 'linux'):
                modern = next(p for p in artifacts if p.name.startswith(f'microlnsight-{system}'))
                bridge = next(p for p in artifacts if p.name.startswith(f'winsecagent-{system}'))
                new_files = cli_update.unpack(modern.read_bytes(), system, cli_update.VERSION)
                old_files = legacy.unpack(bridge.read_bytes(), system, cli_update.VERSION)
                self.assertEqual(new_files, old_files)
                self.assertEqual(json.loads(new_files['edition.json'])['product'], 'Microlnsight')
                with self.assertRaises(ValueError):
                    legacy.unpack(modern.read_bytes(), system, cli_update.VERSION)

    def test_old_updater_discovers_and_installs_bridge_then_new_updater_selects_modern(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as directory:
            base = Path(directory)
            system = platform.system().lower()
            old_release = build(base / 'old', '0.2.6')
            bridge = next(p for p in old_release if p.name.startswith(f'winsecagent-{system}'))
            files = legacy.unpack(bridge.read_bytes(), system, '0.2.6')
            files['cli_update.py'] = Path(legacy.__file__).read_bytes()
            files['SHA256SUMS.txt'] = ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n'
                for name, data in sorted(files.items()) if name != 'SHA256SUMS.txt').encode()
            root = base / 'installed'
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            private = root / 'data/agent.guard/models.json'
            private.parent.mkdir(parents=True)
            private.write_bytes(b'private configuration')
            tasks = private.with_name('tasks.db')
            tasks.write_bytes(b'private task history')
            (root / '.env').write_bytes(b'private environment')
            artifacts = build(base / 'new')
            tag = 'cli-v' + cli_update.VERSION
            url = f'https://github.com/{cli_update.REPOSITORY}/releases/download/{tag}/'
            assets = [*artifacts, base / 'new/SHA256SUMS.txt']
            release = dict(tag_name=tag, assets=[dict(name=p.name, browser_download_url=url + p.name) for p in assets])
            responses = {url + p.name: p.read_bytes() for p in assets}
            responses[f'https://api.github.com/repos/{cli_update.REPOSITORY}/releases?per_page=30'] = json.dumps([release]).encode()
            with patch.dict(os.environ, {'MICROLNSIGHT_UPDATE_TOKEN': '', 'WINSEC_UPDATE_TOKEN': ''}), \
                    patch.object(legacy, 'download', side_effect=lambda url, *args: responses[url]), \
                    patch.object(legacy, 'runtime_python', return_value=Path(sys.executable)):
                info = legacy.check(root)
                self.assertTrue(info['filename'].startswith('winsecagent-'))
                self.assertTrue(legacy.apply(root, info, progress=lambda _: None))
            self.assertEqual(cli_update.installed(root)['version'], cli_update.VERSION)
            self.assertEqual(private.read_bytes(), b'private configuration')
            self.assertEqual(tasks.read_bytes(), b'private task history')
            self.assertEqual((root / '.env').read_bytes(), b'private environment')
            with patch.dict(os.environ, {'MICROLNSIGHT_UPDATE_TOKEN': '', 'WINSEC_UPDATE_TOKEN': ''}), \
                    patch('cli_update.download', side_effect=lambda url, *args: responses[url]):
                self.assertTrue(cli_update.check(root)['filename'].startswith('microlnsight-'))

    def test_mixed_archive_roots_are_rejected(self):
        import io
        import zipfile
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('microlnsight-windows-cli/agent.py', b'')
            bundle.writestr('winsecagent-windows-cli/cli.py', b'')
        with self.assertRaisesRegex(ValueError, '目录'):
            cli_update.unpack(archive.getvalue(), 'windows', cli_update.VERSION)


if __name__ == '__main__':
    unittest.main()
