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
    def windows_row(self, record=1, event_id=4624, ip='-', logon_type='5'):
        return dict(EventID=event_id, Channel='Security', Computer='WIN-TEST', RecordId=record,
                    TimeCreated='2026-10-14T06:00:00Z',
                    EventData=dict(TargetUserName='service-test', TargetDomainName='LAB',
                                   IpAddress=ip, LogonType=logon_type))

    def test_service_logons_without_ip_remain_evidence_without_ip_findings(self):
        rows = [self.windows_row(i + 1) for i in range(30)]
        reasons, diagnostics = {}, {}
        events, rejected = guard.windows_events(rows, reasons, diagnostics)
        self.assertEqual((len(events), rejected), (30, 0))
        self.assertEqual(reasons, {})
        self.assertEqual(diagnostics['source_ip_status'], {'not_recorded': 30})
        self.assertEqual(diagnostics['logon_types'], {'5': 30})
        self.assertTrue(all(e['ip'] is None and e['logon_type'] == '5' for e in events))
        result = guard.detect(dict(events=events, rejected=rejected, windows_diagnostics=diagnostics))
        self.assertEqual(result['coverage']['retained'], 30)
        self.assertEqual(result['coverage']['ip_rule_eligible'], 0)
        self.assertEqual(result['coverage']['retained_without_ip'], 30)
        self.assertEqual(result['findings'], [])
        self.assertEqual(guard.task_assessment(result)['status'], 'insufficient_data')
        self.assertIn('已保留登录证据', guard.task_assessment(result)['label'])
        self.assertEqual(guard.task_scope(result)['reasons'][0]['code'], 'source_ip_unavailable')
        result.update(id='test', source='windows-local', demo=False, actions=[])
        evidence = models.context(result)['evidence']
        self.assertTrue(evidence)
        self.assertTrue(all(e['ip'] is None and e['logon_type'] == '5' for e in evidence))

    def test_missing_or_invalid_ip_never_fabricates_source_correlation(self):
        rows = [self.windows_row(i + 1, event_id=4625, ip='-' if i < 6 else 'bad-ip', logon_type='3')
                for i in range(12)]
        events, rejected = guard.windows_events(rows)
        result = guard.detect(dict(events=events, rejected=rejected))
        self.assertEqual(result['coverage']['retained'], 12)
        self.assertEqual(result['findings'], [])
        self.assertEqual(guard.plan(result['findings']), [])
        self.assertEqual(events[-1]['source_ip_status'], 'invalid')
        valid = [self.windows_row(100 + i, event_id=4625, ip='192.0.2.1', logon_type='3') for i in range(5)]
        more, _ = guard.windows_events(valid)
        mixed = guard.detect(dict(events=events + more, rejected=0))
        self.assertEqual(mixed['coverage']['ip_rule_eligible'], 5)
        self.assertEqual(len(mixed['findings']), 1)
        self.assertEqual(mixed['findings'][0]['failure_count'], 5)
        self.assertEqual(mixed['findings'][0]['ip'], '192.0.2.1')

    def test_exclusions_identify_event_ids_and_each_missing_required_field(self):
        row = self.windows_row()
        diagnostics, reasons = {}, {}
        events, rejected = guard.windows_events([
            {**row, 'EventID': 9998}, {**row, 'EventID': 9999},
            {**row, 'Computer': '', 'RecordId': 0, 'TimeCreated': 'invalid',
             'EventData': {'IpAddress': '-', 'LogonType': '5'}},
        ], reasons, diagnostics)
        self.assertEqual((events, rejected), ([], 3))
        self.assertEqual(reasons, {'unsupported': 2, 'missing_metadata': 1})
        self.assertEqual(diagnostics['unsupported_event_ids'], {'9998': 1, '9999': 1})
        self.assertEqual(diagnostics['missing_fields'], {'record_id': 1, 'timestamp': 1, 'computer': 1, 'username': 1})
        result = guard.detect(dict(events=[], rejected=rejected, rejected_reasons=reasons,
                                   windows_diagnostics=diagnostics))
        scope = guard.task_scope(result)
        text = json.dumps(scope, ensure_ascii=False)
        self.assertIn('9998', text)
        self.assertIn('目标账户 1 条', text)
        self.assertNotIn('source_ip', diagnostics['missing_fields'])

    def test_windows_collector_filters_before_limit_and_keeps_scope_metadata(self):
        sys.path.insert(0, str(ROOT / 'backend'))
        rows = [self.windows_row()]
        with patch('platform.system', return_value='Windows'), \
                patch('app.services.log_reader.read_windows_logs', return_value=dict(events=rows,
                      is_mock=False, read_status='success', channel_results=[dict(status='success', events_read=1)])) as read:
            result = guard.collect_windows(limit=1000)
        self.assertEqual(read.call_count, 8)
        self.assertEqual(read.call_args_list[0].kwargs['event_ids'], [4624, 4625])
        self.assertEqual(sum(c.kwargs['max_events'] for c in read.call_args_list), 1000)
        self.assertEqual(len(result['events']), 8)
        self.assertFalse(result['collection']['limit_reached'])
        self.assertEqual(set(result['collection']['event_ids']), {4624, 4625, 5379, 4672, 4627, 4798, 4799, 5058, 5061})
        self.assertEqual(result['windows_diagnostics']['event_ids'], {'4624': 8})

    def test_windows_native_query_filters_server_side_and_closes_handles(self):
        sys.path.insert(0, str(ROOT / 'backend'))
        from app.services import log_reader
        native = Mock()
        native.EvtQueryReverseDirection = 512
        handle = Mock()
        native.EvtNext.return_value = [handle]
        native.EvtRender.return_value = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System><EventID>4624</EventID><Channel>Security</Channel><Computer>WIN-TEST</Computer>
        <EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-10-14T06:00:00Z"/></System>
        <EventData><Data Name="TargetUserName">service-test</Data><Data Name="LogonType">5</Data>
        <Data Name="IpAddress">-</Data></EventData></Event>'''
        with patch.dict(sys.modules, win32evtlog=native):
            rows, channels = log_reader._read_real_logs(['Security'], 1, [4624, 4625])
        native.EvtQuery.assert_called_once_with('Security', 512, '*[System[(EventID=4624 or EventID=4625)]]')
        handle.Close.assert_called_once()
        native.EvtQuery.return_value.Close.assert_called_once()
        self.assertEqual(channels[0]['events_read'], 1)
        events, rejected = guard.windows_events(rows)
        self.assertEqual((len(events), rejected), (1, 0))
        self.assertEqual(events[0]['logon_type'], '5')
        self.assertEqual(log_reader._event_query(None), '*')
        for invalid in ([], ['4624'], [True], [-1], [65536], ['4624) or *']):
            with self.assertRaises(ValueError):
                log_reader._event_query(invalid)

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
                self.assertIn('尚未执行', result.stdout)
            tasks = subprocess.run(prefix + ['tasks'], capture_output=True, text=True, encoding='utf-8', timeout=30)
            self.assertIn('demo-windows', tasks.stdout)
            self.assertIn('demo-linux', tasks.stdout)


class ModelTests(unittest.TestCase):
    def response(self, payload, status=200):
        response = Mock(status_code=status)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.iter_content.return_value = [json.dumps(payload).encode()]
        return response

    def test_old_deepseek_profile_gets_safe_defaults_without_altering_other_providers(self):
        profile = dict(kind='openai', base_url='https://api.deepseek.com', model='deepseek-v4-pro')
        response = self.response({'choices': [{'message': {'content': 'ok'}, 'finish_reason': 'stop'}]})
        with patch('requests.post', return_value=response) as post:
            models.generate(profile, 'private-key', [])
            body = post.call_args.kwargs['json']
            self.assertEqual(body['thinking'], {'type': 'disabled'})
            self.assertEqual(body['max_tokens'], 4096)
            models.generate({**profile, 'thinking': 'enabled'}, '', [])
            self.assertEqual(post.call_args.kwargs['json']['max_tokens'], 16384)
            models.generate({**profile, 'base_url': 'https://api.deepseek.com.example/v1'}, '', [])
            self.assertNotIn('thinking', post.call_args.kwargs['json'])

    def test_model_parameter_bounds_and_no_foreign_provider_thinking_flags(self):
        profile = dict(kind='openai', base_url='https://example.com/v1', model='test')
        for extra in ({'max_tokens': 0}, {'max_tokens': True}, {'max_tokens': 65537},
                      {'timeout_seconds': 601}, {'thinking': 'enabled'}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                models.validate({**profile, **extra})

    def test_finish_reasons_empty_answers_and_malformed_responses_are_distinct(self):
        profile = dict(kind='openai', base_url='https://api.deepseek.com', model='deepseek-v4-pro')
        cases = [
            ({'choices': [{'message': {'content': '', 'reasoning_content': 'private-reasoning'}, 'finish_reason': 'length'}]}, 'output_limit'),
            ({'choices': [{'message': {'content': 'incomplete answer'}, 'finish_reason': 'length'}]}, 'output_limit'),
            ({'choices': [{'message': {'content': '', 'reasoning_content': 'private-reasoning'}, 'finish_reason': 'stop'}]}, 'reasoning_without_answer'),
            ({'choices': [{'message': {'content': ''}, 'finish_reason': 'stop'}]}, 'empty_answer'),
            ({'choices': [{'message': {'content': 'partial'}, 'finish_reason': 'content_filter'}]}, 'unfinished_response'),
            ({'choices': [{'message': {'content': None}, 'finish_reason': 'tool_calls'}]}, 'unfinished_response'),
            ({'choices': []}, 'invalid_structure'),
            ([], 'invalid_structure'),
        ]
        for payload, code in cases:
            with self.subTest(code=code), patch('requests.post', return_value=self.response(payload)) as post:
                with self.assertRaises(models.ModelError) as caught:
                    models.generate(profile, 'private-key', [])
                self.assertEqual(caught.exception.diagnostic['code'], code)
                self.assertNotIn('private-reasoning', str(caught.exception.diagnostic))
                self.assertNotIn('private-key', str(caught.exception))
                post.assert_called_once()

    def test_invalid_json_http_timeout_and_network_errors_have_safe_diagnostics(self):
        import requests
        profile = dict(kind='openai', base_url='https://api.deepseek.com', model='test')
        response = self.response({}, 401)
        with patch('requests.post', return_value=response), self.assertRaises(models.ModelError) as caught:
            models.generate(profile, 'secret', [])
        self.assertEqual(caught.exception.diagnostic, {'code': 'http_error', 'http_status': 401})
        response.status_code = 200
        response.iter_content.return_value = [b'<html>private proxy response</html>']
        with patch('requests.post', return_value=response), self.assertRaises(models.ModelError) as caught:
            models.generate(profile, '', [])
        self.assertEqual(caught.exception.diagnostic['code'], 'invalid_json')
        for error, code in [(requests.Timeout('private-url'), 'timeout'), (requests.ConnectionError('private-url'), 'connection_error')]:
            with patch('requests.post', side_effect=error), self.assertRaises(models.ModelError) as caught:
                models.generate(profile, '', [])
            self.assertEqual(caught.exception.diagnostic['code'], code)
            self.assertNotIn('private-url', str(caught.exception))

    def test_failure_metadata_is_persisted_and_sent_on_followup_without_failed_answer(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as directory:
            store = guard.TaskStore(Path(directory) / 'tasks.db')
            task = guard.run_task(store, 'demo', lambda: guard.demo_events('linux'))
            profiles = models.Profiles(Path(directory) / 'models.json')
            profiles.put('local', dict(kind='ollama', base_url='http://localhost:11434', model='test'))
            payload = {'message': {'content': '', 'thinking': 'private-reasoning'}, 'done_reason': 'length',
                       'usage': {'completion_tokens': 1200, 'completion_tokens_details': {'reasoning_tokens': 1200}}}
            with patch('requests.post', return_value=self.response(payload)), self.assertRaises(models.ModelError):
                models.ask(store, profiles, task['id'], 'explain')
            self.assertEqual(store.history(task['id']), [])
            diagnostic = models.context(store.get(task['id']))['model_diagnostic']
            self.assertEqual(diagnostic['completion_tokens'], 1200)
            self.assertEqual(diagnostic['reasoning_tokens'], 1200)
            self.assertNotIn('private-reasoning', json.dumps(store.get(task['id'])))
            with patch('guard_models.generate', return_value='ok') as generate:
                models.ask(store, profiles, task['id'], 'why failed?')
            self.assertIn('output_limit', str(generate.call_args.args[2]))
            self.assertEqual(store.get(task['id'])['last_model_diagnostic'], {'code': 'success'})

    def test_automatic_analysis_keeps_model_diagnostics_without_marking_model_success(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as directory:
            store = guard.TaskStore(Path(directory) / 'tasks.db')
            def analyst(task_id):
                raise models.ModelError('output stopped', 'output_limit', finish_reason='length')
            task = guard.run_task(store, 'demo', lambda: guard.demo_events('linux'), analyst=analyst)
            self.assertEqual(task['model_diagnostic']['code'], 'output_limit')
            self.assertNotIn('model_answer', task)
            self.assertEqual(task['status'], 'completed_simulation')

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
