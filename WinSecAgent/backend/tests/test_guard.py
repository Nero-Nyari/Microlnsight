"""Cross-platform contracts; no SSH, OS mutation or real model traffic."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import guard
import guard_models as models


class GuardTests(unittest.TestCase):
    def test_dedup_conflicts_and_host_boundaries(self):
        collection = guard.demo_events('linux')
        original = deepcopy(collection)
        collection['events'] += deepcopy(collection['events'])
        result = guard.detect(collection)
        self.assertEqual(result['coverage']['duplicates'], 7)
        self.assertEqual(result['findings'][0]['failure_count'], 6)
        conflict = deepcopy(collection['events'][0])
        conflict['ip'] = '192.0.2.99'
        collection['events'].append(conflict)
        self.assertEqual(guard.detect(collection)['coverage']['conflicts'], 3)
        for row in original['events'][:3]:
            row['host'] = 'different-host'
        self.assertEqual(guard.detect(original)['findings'], [])

    def test_single_failure_and_time_window_do_not_claim_attack(self):
        data = guard.demo_events('windows')
        data['events'] = data['events'][:1]
        self.assertEqual(guard.detect(data)['findings'], [])
        data = guard.demo_events('linux')
        base = guard.utcnow()
        for i, row in enumerate(data['events']):
            row['time'] = (base + timedelta(minutes=i * 6)).isoformat()
        self.assertEqual(guard.detect(data)['findings'], [])

    def test_windows_normalization_preserves_platform_identity_and_ignores_other_channels(self):
        row = dict(EventID=4625, Channel='Security', Computer='WIN-1', RecordId=10,
                   TimeCreated='2026-10-12T00:00:00Z',
                   EventData=dict(TargetUserName='admin', IpAddress='::ffff:192.0.2.3'))
        events, rejected = guard.windows_events([row, {**row, 'Channel': 'Application'}, {**row, 'RecordId': None}])
        self.assertEqual(rejected, 2)
        self.assertEqual(events[0]['ip'], '192.0.2.3')
        self.assertEqual(events[0]['platform'], 'windows')

    def test_linux_journal_and_text_require_sshd_host_time_and_valid_ip(self):
        row = dict(MESSAGE='Failed password for root from 192.0.2.1 port 4000 ssh2',
                   _HOSTNAME='linux-1', __REALTIME_TIMESTAMP='1791763200000000',
                   __CURSOR='cursor-1', SYSLOG_IDENTIFIER='sshd')
        text = '\n'.join([json.dumps(row), json.dumps({**row, 'SYSLOG_IDENTIFIER': 'app'}),
                          '2026-10-12T00:00:00+00:00 linux-1 sshd[12]: Accepted publickey for root from 192.0.2.1 port 44 ssh2',
                          'Oct 12 00:00:00 linux-1 sshd[12]: Failed password for root from 192.0.2.1 port 44',
                          '{broken json}'])
        events, rejected = guard.linux_events(text)
        self.assertEqual(len(events), 2)
        self.assertEqual(rejected, 3)
        self.assertEqual(events[1]['kind'], 'success')

    def test_policy_protection_and_simulation_verification(self):
        findings = guard.detect(guard.demo_events('windows'))['findings']
        protected = guard.plan(findings, ['192.0.2.0/24'])
        self.assertEqual(protected[0]['status'], 'protected_skipped')
        actions = guard.plan(findings)
        with patch('subprocess.run', side_effect=AssertionError('must not execute')):
            guard.simulate(actions)
        self.assertTrue(actions[0]['simulation_verified'])
        self.assertFalse(actions[0]['actual_system_change'])
        self.assertEqual(actions[0]['verification'], 'not_performed')
        with self.assertRaises(ValueError):
            guard.plan(findings, ttl=0)
        with self.assertRaises(ValueError):
            guard.plan(findings, ['not-an-ip'])

    def test_restart_task_audit_idempotence_and_failure_are_persistent(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend' / 'data') as directory:
            path = Path(directory) / 'tasks.db'
            store = guard.TaskStore(path)
            data = guard.demo_events('linux')
            first = guard.run_task(store, 'demo', lambda: data, demo=True)
            restarted = guard.TaskStore(path)
            second = guard.run_task(restarted, 'demo', lambda: data, demo=True)
            self.assertEqual(second['actions'][0]['status'], 'duplicate_skipped')
            self.assertEqual(second['actions'][0]['previous_task'], first['id'])
            self.assertEqual(restarted.get(first['id'])['status'], 'completed_simulation')
            with self.assertRaises(RuntimeError):
                guard.run_task(store, 'bad-ssh', Mock(side_effect=RuntimeError('authentication failed')))
            self.assertEqual(store.recent()[0]['status'], 'failed')

    def test_model_failure_does_not_fabricate_answer_or_change_policy(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend' / 'data') as directory:
            store = guard.TaskStore(Path(directory) / 'tasks.db')
            task = guard.run_task(store, 'demo', lambda: guard.demo_events('linux'),
                                  analyst=Mock(side_effect=RuntimeError('model timeout')))
            self.assertNotIn('model_answer', task)
            self.assertIn('model timeout', task['model_error'])
            self.assertFalse(task['actions'][0]['actual_system_change'])

    def test_ssh_command_is_fixed_key_only_and_failure_not_empty_success(self):
        with patch('guard.subprocess.run') as run:
            run.return_value = Mock(returncode=0, stdout=b'', stderr=b'No journal files were found.')
            result = guard.collect_linux('root@192.0.2.1', 15, 100)
            argv = run.call_args.args[0]
            self.assertIn('BatchMode=yes', argv)
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertNotIn('shell', run.call_args.kwargs)
            self.assertTrue(result['warnings'])
            run.return_value = Mock(returncode=255, stdout=b'', stderr=b'Permission denied')
            with self.assertRaisesRegex(RuntimeError, 'Permission denied'):
                guard.collect_linux('root@192.0.2.1')
            run.side_effect = subprocess.TimeoutExpired('ssh', 45)
            with self.assertRaisesRegex(RuntimeError, '超时'):
                guard.collect_linux('lab')
        for value in ('-oProxyCommand=bad', 'root@host; id', 'host\ncommand'):
            with self.assertRaises(ValueError):
                guard.ssh_target(value)

    def test_export_is_read_only_and_tracks_input_hash(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend' / 'data') as directory:
            path = Path(directory) / 'ssh.journal.log'
            content = '2026-10-12T00:00:00+00:00 lab sshd[1]: Failed password for root from 192.0.2.1 port 123\n'
            path.write_text(content, encoding='utf-8')
            before = path.read_bytes()
            result = guard.collect_export(directory)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(len(result['events']), 1)
            self.assertTrue(result['source_sha256'])

    def test_cli_demo_both_platforms_and_history(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend' / 'data') as directory:
            prefix = [sys.executable, '-X', 'utf8', str(ROOT / 'cli.py'), '--database', str(Path(directory) / 'cli.db')]
            for platform in ('windows', 'linux'):
                result = subprocess.run(prefix + ['guard', f'demo-{platform}'], capture_output=True,
                                        text=True, encoding='utf-8', timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('合成演示数据', result.stdout)
                self.assertIn('模拟器自检', result.stdout)
            tasks = subprocess.run(prefix + ['tasks'], capture_output=True, text=True, encoding='utf-8', timeout=30)
            self.assertIn('demo-windows', tasks.stdout)
            self.assertIn('demo-linux', tasks.stdout)


class ModelTests(unittest.TestCase):
    def test_local_without_key_and_keys_never_saved(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend' / 'data') as directory:
            profiles = models.Profiles(Path(directory) / 'models.json')
            profiles.put('local', dict(kind='ollama', base_url='http://127.0.0.1:11434', model='example'))
            name, profile = profiles.active()
            self.assertEqual(name, 'local')
            self.assertEqual(profiles.key(name, profile), '')
            profiles.put('api', dict(kind='openai', base_url='https://model.example/v1', model='example', key_env='LAB_MODEL_KEY'), 'never-save-this')
            self.assertNotIn('never-save-this', profiles.path.read_text())
            self.assertEqual(profiles.key(*profiles.active()), 'never-save-this')
            profiles.activate('local')
            self.assertEqual(profiles.active()[0], 'local')

    def test_remote_consent_blocks_network_and_followup_has_evidence(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend' / 'data') as directory:
            store = guard.TaskStore(Path(directory) / 'tasks.db')
            task = guard.run_task(store, 'demo', lambda: guard.demo_events('linux'))
            profiles = models.Profiles(Path(directory) / 'models.json')
            profiles.put('remote', dict(kind='openai', base_url='https://model.example/v1', model='example'))
            with patch('guard_models.generate', return_value='参考 demo:0，请核对授权') as generate:
                with self.assertRaisesRegex(ValueError, '确认发送'):
                    models.ask(store, profiles, task['id'], '发生了什么？')
                generate.assert_not_called()
                models.ask(store, profiles, task['id'], '发生了什么？', consent=True)
                models.ask(store, profiles, task['id'], '然后查什么？', consent=True)
                messages = generate.call_args.args[2]
                self.assertIn('参考 demo:0', str(messages))
                self.assertIn('不可信', messages[0]['content'])
                self.assertEqual(len(store.history(task['id'])), 4)
                self.assertEqual(store.get(task['id'])['status'], 'completed_simulation')

    def test_both_wire_protocols_and_no_redirect_or_fallback(self):
        profile = dict(kind='ollama', base_url='http://127.0.0.1:11434', model='test')
        response = Mock(status_code=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch('requests.post', return_value=response) as post:
            response.iter_content.return_value = [b'{"message":{"content":"ok"}}']
            self.assertEqual(models.generate(profile, '', []), 'ok')
            self.assertTrue(post.call_args.args[0].endswith('/api/chat'))
            self.assertFalse(post.call_args.kwargs['allow_redirects'])
            profile.update(kind='openai', base_url='https://model.example/v1')
            response.iter_content.return_value = [b'{"choices":[{"message":{"content":"api-ok"}}]}']
            self.assertEqual(models.generate(profile, 'secret', []), 'api-ok')
            self.assertEqual(post.call_args.kwargs['headers']['Authorization'], 'Bearer secret')
            response.status_code = 401
            with self.assertRaisesRegex(RuntimeError, 'HTTP 401'):
                models.generate(profile, 'secret', [])
            response.status_code = 302
            with self.assertRaisesRegex(RuntimeError, 'HTTP 302'):
                models.generate(profile, 'secret', [])


if __name__ == '__main__':
    unittest.main()
