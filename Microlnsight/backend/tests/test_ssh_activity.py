"""SSH lifecycle coverage and bounded local evidence, using synthetic records."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import guard
import guard_cli
import guard_models
import server_logs
from terminal_ui import Cancelled


OPEN = [
    'Connection from 192.0.2.10 port 50000 on 192.0.2.20 port 22 rdomain ""',
    'Accepted password for tester from 192.0.2.10 port 50000 ssh2',
    'pam_unix(sshd:session): session opened for user tester by (uid=0)',
    'User child is on pid 1234',
    'Starting session: shell on pts/0 for tester from 192.0.2.10 port 50000 id 0',
]
CLOSE = [
    'Connection closed by 192.0.2.10 port 50000',
    'Close session: user tester from 192.0.2.10 port 50000 id 0',
    'Transferred: sent 5748, received 3384 bytes',
    'Closing connection to 192.0.2.10 port 50000',
    'pam_unix(sshd:session): session closed for user tester',
]


def journal(messages):
    return '\n'.join(json.dumps(dict(_COMM='sshd', _HOSTNAME='synthetic-host',
        __REALTIME_TIMESTAMP=str(1792117658000000 + n * 1000000), __CURSOR=f'test:{n}',
        MESSAGE=message)) for n, message in enumerate(messages))


def collection(messages):
    result = Mock(returncode=0, stdout=journal(messages).encode(), stderr=b'')
    with patch('guard.subprocess.run', return_value=result):
        return guard.collect_linux()


class SshActivityTests(unittest.TestCase):
    def test_three_authentications_and_twenty_two_activity_records(self):
        result = guard.detect(collection(OPEN + CLOSE + OPEN + CLOSE + OPEN))
        self.assertEqual(result['coverage']['input'], 25)
        self.assertEqual(result['coverage']['retained'], 25)
        self.assertEqual(result['coverage']['ssh_auth_retained'], 3)
        self.assertEqual(result['coverage']['ssh_activity_retained'], 22)
        self.assertEqual(result['coverage']['ip_rule_eligible'], 3)
        self.assertEqual(result['coverage']['excluded'], 0)
        self.assertEqual(result['findings'], [])
        self.assertFalse(guard.task_scope(result)['incomplete'])
        self.assertIn('登录认证 3 条，会话活动 22 条', guard.task_scope(result)['summary'])
        child = next(r for r in result['events'] if r.get('activity') == 'child_process')
        self.assertIsNone(child['ip'])
        self.assertIsNone(child['account'])

    def test_activities_do_not_count_as_success_or_suppress_failure_detection(self):
        failures = ['Failed password for tester from 192.0.2.10 port 50000 ssh2'] * 5
        result = guard.detect(collection(failures + [OPEN[0], OPEN[2], OPEN[3]]))
        self.assertEqual(result['findings'][0]['rule'], 'auth_repeated_failure')
        self.assertEqual(result['findings'][0]['failure_count'], 5)
        result = guard.detect(collection([OPEN[0], OPEN[2], OPEN[3]]))
        self.assertEqual(guard.task_assessment(result)['status'], 'insufficient_data')
        result = guard.detect(collection(failures + OPEN))
        self.assertEqual(result['findings'][0]['rule'], 'auth_failure_then_success')

    def test_shared_parser_requires_source_host_time_and_valid_explicit_ip(self):
        for message in OPEN + CLOSE:
            with self.subTest(message=message):
                row = json.loads(journal([message]))
                parsed, reason = server_logs.parse_ssh_line(json.dumps(row))
                self.assertIsNotNone(parsed, reason)
                row['_COMM'] = 'web-app'
                self.assertEqual(server_logs.parse_ssh_line(json.dumps(row))[1], 'unknown_source')
                text = f'2026-10-16T10:27:38+0800 synthetic-host sshd[123]: {message}'
                self.assertIsNotNone(server_logs.parse_ssh_line(text)[0])
        for field in ('_HOSTNAME', '__REALTIME_TIMESTAMP'):
            row = json.loads(journal([OPEN[0]]))
            del row[field]
            self.assertEqual(server_logs.parse_ssh_line(json.dumps(row))[1], 'missing_metadata')
        invalid_ip = OPEN[0].replace('192.0.2.10', 'not-an-ip')
        self.assertEqual(server_logs.parse_ssh_line(journal([invalid_ip]))[1], 'missing_metadata')
        self.assertEqual(server_logs.parse_ssh_line(journal([OPEN[3] + ' malicious suffix']))[1], 'unsupported')

    def test_offline_report_does_not_count_session_activity_as_authentication(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as temp:
            Path(temp, 'ssh.journal.log').write_text(journal(OPEN + CLOSE + OPEN + CLOSE + OPEN), encoding='utf-8')
            result = server_logs.analyze_directory(temp)
            self.assertEqual(result['ssh']['accepted'], 3)
            self.assertEqual(result['ssh']['session_activity'], 22)
            self.assertEqual(result['ssh']['correlation_excluded'], 0)
            self.assertIn('22 条 SSH 会话活动', server_logs.render_report(result))
            native = guard.detect(guard.collect_export(temp))
            self.assertEqual(native['coverage']['ssh_activity_retained'], 22)
            Path(temp, 'ssh.journal.log').write_text(journal([OPEN[0], OPEN[2], OPEN[3]]), encoding='utf-8')
            self.assertEqual(server_logs.analyze_directory(temp)['analysis_status'], 'insufficient_data')

    def test_duplicate_or_conflicting_activity_is_not_silently_counted(self):
        event = collection([OPEN[0]])['events'][0]
        result = guard.detect(dict(events=[event, dict(event)], rejected=0))
        self.assertEqual(result['coverage']['ssh_activity_retained'], 1)
        self.assertEqual(result['coverage']['duplicates'], 1)
        result = guard.detect(dict(events=[event, {**event, 'ip': '192.0.2.99'}], rejected=0))
        self.assertEqual(result['coverage']['conflicts'], 2)
        self.assertEqual(result['coverage']['retained'], 0)
        self.assertTrue(guard.task_scope(result)['incomplete'])

    def test_rejected_evidence_survives_store_export_and_is_not_sent_to_model(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'backend/data') as temp:
            store, profiles = guard_cli.resources(Path(temp) / 'agent.db')
            task = guard.run_task(store, 'linux:local', lambda: collection(OPEN + ['UNKNOWN_LOCAL_ONLY']))
            task = store.get(task['id'])
            self.assertEqual(task['excluded_records'][0]['reason'], 'unsupported')
            self.assertEqual(task['excluded_records'][0]['ref'], 'ssh:6')
            payload = guard_models.context(task)
            self.assertNotIn('UNKNOWN_LOCAL_ONLY', json.dumps(payload))
            self.assertTrue(any(r.get('activity') == 'child_process' for r in payload['evidence']))
            self.assertEqual(payload['evidence_scope']['retained_records'], 5)
            output_path = Path(temp) / 'report.json'
            with patch('guard_cli.choice', side_effect=['4', '3', Cancelled()]), \
                    patch('guard_cli.field', return_value=output_path), redirect_stdout(io.StringIO()) as output:
                guard_cli.task_detail(store, profiles, task)
            self.assertIn('UNKNOWN_LOCAL_ONLY', output.getvalue())
            self.assertIn('消息暂不支持', output.getvalue())
            self.assertEqual(json.loads(output_path.read_text(encoding='utf-8'))['task']['excluded_records'], task['excluded_records'])
            with redirect_stdout(io.StringIO()) as output:
                guard_cli.show_evidence({'coverage': {'excluded': 22}}, excluded=True)
            self.assertIn('未保存排除记录原文', output.getvalue())

    def test_record_and_byte_limits_are_explicit_with_hashes(self):
        text = journal(['unrecognized ' + '中' * 40] * 8)
        capture, reasons = {}, {}
        with patch('guard.MAX_EXCLUDED_RECORDS', 2), patch('guard.MAX_EXCLUDED_RAW_BYTES', 100), \
                patch('guard.MAX_EXCLUDED_BYTES', 150):
            _, rejected = guard.linux_events(text, reasons, capture)
        self.assertEqual(rejected, 8)
        self.assertEqual(capture['total'], 8)
        self.assertEqual(len(capture['records']), 2)
        self.assertEqual(capture['omitted'], 6)
        self.assertLessEqual(capture['raw_bytes'], 150)
        self.assertTrue(all(r['raw_truncated'] for r in capture['records']))
        self.assertEqual(capture['records'][0]['raw_sha256'], hashlib.sha256(text.splitlines()[0].encode()).hexdigest())
        capture = {}
        with patch('guard.MAX_EXCLUDED_RECORDS', 1):
            guard.linux_events(journal(['unknown'] * 3), {}, capture)
        self.assertEqual(capture['omitted'], 2)

    def test_rejected_reason_kept_for_each_record_and_view_paginates(self):
        text = journal(['unknown']) + '\n{broken\n2026-10-16T10:00:00+0800 h app[1]: nope'
        capture, reasons = {}, {}
        guard.linux_events(text, reasons, capture)
        self.assertEqual([r['reason'] for r in capture['records']], ['unsupported', 'invalid', 'unknown_source'])
        rows = [dict(ref=f'ssh:{n}', kind='failure', raw=f'RAW_{n}') for n in range(101)]
        with patch('guard_cli.choice', return_value='1') as choice, redirect_stdout(io.StringIO()) as output:
            guard_cli.show_evidence({'events': rows})
        choice.assert_called_once()
        self.assertIn('RAW_100', output.getvalue())


if __name__ == '__main__':
    unittest.main()
