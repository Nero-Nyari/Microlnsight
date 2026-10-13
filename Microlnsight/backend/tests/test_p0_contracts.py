"""P0 acceptance: source identity and honest outcomes across CLI entry points."""
from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'backend'))
import guard
import guard_cli
from server_logs import analyze_directory, render_console, render_report
from app.services.correlation import analyze_records, record
from app.agents.report_agent import correlation_report


class P0Contracts(unittest.TestCase):
    def directory(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / 'backend/data', prefix='p0-test-')
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def windows(self, values):
        return analyze_records([record(SimpleNamespace(id=i + 1, raw_content=json.dumps(value),
                                                       source_type='windows_log'))
                                for i, value in enumerate(values)])

    def windows_event(self):
        return dict(EventID=4625, Channel='Security', Computer='host', RecordId=1,
                    TimeCreated='2026-10-12T02:00:00Z',
                    EventData=dict(TargetUserName='alice', IpAddress='192.0.2.1'))

    def test_both_ssh_entry_points_reject_forged_origin_and_invalid_metadata(self):
        message = 'Failed password for alice from 192.0.2.1 port 4000 ssh2'
        header = '2026-10-12T10:00:00+08:00 host '
        row = dict(MESSAGE=message, _HOSTNAME='host', __REALTIME_TIMESTAMP='1791770400000000',
                   _COMM='sshd', SYSLOG_IDENTIFIER='sshd', __CURSOR='sample')
        cases = [
            (header + 'webapp[1]: ' + message, False),
            (header + 'sshd[1]: quoted: ' + message, False),
            (header + 'sshd[1]: ' + message, True),
            (header + 'sshd-session[2]: ' + message, True),
            (header + 'sshd-auth[3]: ' + message, True),
            (header + 'sshd: ' + message, True),
            ((header + 'sshd[1]: ' + message).replace('+08:00', ''), False),
            ((header + 'sshd[1]: ' + message).replace('192.0.2.1', '0.0.0.0'), False),
            (json.dumps(row), True),
            (json.dumps({**row, '_COMM': 'webapp'}), False),
            (json.dumps({**row, '_HOSTNAME': ''}), False),
            (json.dumps({**row, '__REALTIME_TIMESTAMP': None}), False),
            ('{bad json', False),
        ]
        root = self.directory()
        for line, accepted in cases:
            with self.subTest(line=line):
                path = root / 'ssh.journal.log'
                path.write_text(line + '\n', encoding='utf-8')
                before = path.read_bytes()
                offline = analyze_directory(root)
                native, rejected = guard.linux_events(line)
                self.assertEqual(offline['ssh']['failed'], int(accepted))
                self.assertEqual(len(native), int(accepted))
                self.assertEqual(offline['ssh']['correlation_excluded'], rejected)
                self.assertEqual(offline['analysis_status'], 'no_findings' if accepted else 'insufficient_data')
                self.assertEqual(path.read_bytes(), before)
                self.assertIn(offline['assessment'], render_report(offline))
                self.assertIn(offline['assessment'], render_console(offline))
                if accepted:
                    self.assertEqual(native[0]['time'], offline['files']['ssh.journal.log']['start'])

    def test_webapp_messages_cannot_form_offline_ssh_sequence(self):
        root = self.directory()
        (root / 'ssh.journal.log').write_text(
            '2026-10-12T02:00:00Z host webapp[1]: Failed password for root from 192.0.2.1 port 1\n'
            '2026-10-12T02:01:00Z host webapp[1]: Accepted password for root from 192.0.2.1 port 2\n', encoding='utf-8')
        result = analyze_directory(root)
        self.assertEqual(result['ssh']['success_after_failures'], [])
        self.assertEqual(result['ssh']['root_password_success'], 0)
        self.assertEqual(result['ssh']['rejected_reasons']['unknown_source'], 2)
        self.assertIn('无法确认来源 2 条', render_report(result))
        self.assertIn('ssh.journal.log:1', render_report(result))

    def test_windows_empty_invalid_unsupported_and_ineligible_are_insufficient(self):
        good = self.windows_event()
        for values in ([], [{'message': 'unrecognized'}], [{**good, 'EventID': 5379}],
                       [{**good, 'TimeCreated': '2026-10-12T02:00:00'}], [{**good, 'RecordId': None}]):
            with self.subTest(values=values):
                result = self.windows(values)
                self.assertEqual(result['assessment']['status'], 'insufficient_data')
                self.assertEqual(result['coverage']['eligible_records'], 0)
                self.assertIn('数据不足，无法判断', correlation_report('test', result))
                self.assertNotIn('未发现规则线索', result['assessment']['reasoning'])

    def test_valid_and_partial_data_keep_quality_separate_from_verdict(self):
        good = self.windows_event()
        valid = self.windows([good])
        partial = self.windows([good, {'message': 'unrecognized'}])
        for result in (valid, partial):
            self.assertEqual(result['assessment']['status'], 'no_findings')
            self.assertEqual(result['coverage']['eligible_records'], 1)
            self.assertIn(result['assessment']['label'], correlation_report('test', result))
        self.assertFalse(valid['assessment']['scope_incomplete'])
        self.assertTrue(partial['assessment']['scope_incomplete'])
        self.assertIn('分析范围不完整', correlation_report('test', partial))
        root = self.directory()
        line = '2026-10-12T02:00:00Z host sshd[1]: Failed password for alice from 192.0.2.1 port 1'
        (root / 'ssh.journal.log').write_text(line + '\nunrecognized\n', encoding='utf-8')
        server = analyze_directory(root)
        self.assertEqual(server['analysis_status'], 'no_findings')
        self.assertIn('分析范围不完整', render_console(server))
        self.assertIn('分析范围不完整', render_report(server))

    def test_native_outcomes_survive_restart_and_collection_failure(self):
        root = self.directory()
        store = guard.TaskStore(root / 'tasks.db')
        event = guard.demo_events('linux')['events'][0]
        for data, status, incomplete in [
            (dict(events=[], rejected=0), 'insufficient_data', False),
            (dict(events=[], rejected=2), 'insufficient_data', True),
            (dict(events=[event], rejected=0), 'no_findings', False),
            (dict(events=[event], rejected=1), 'no_findings', True),
            (dict(events=[event], rejected=0, scope_incomplete=True), 'no_findings', True),
            (guard.demo_events('linux'), 'findings', False),
        ]:
            with self.subTest(status=status, data=data):
                task = guard.run_task(store, 'test', lambda: deepcopy(data), demo=True)
                task = guard.TaskStore(root / 'tasks.db').get(task['id'])
                self.assertEqual(task['assessment']['status'], status)
                self.assertEqual(task['assessment']['scope_incomplete'], incomplete)
                output = StringIO()
                with redirect_stdout(output):
                    guard_cli.show(task)
                self.assertIn(task['assessment']['label'], output.getvalue())
                if incomplete:
                    self.assertIn('分析范围不完整', output.getvalue())
                if status == 'insufficient_data':
                    self.assertNotIn('未发现规则线索', output.getvalue())
        def failed():
            raise RuntimeError('permission denied')
        with self.assertRaises(RuntimeError):
            guard.run_task(store, 'failed-collection', failed)
        task = store.recent()[0]
        self.assertEqual(task['assessment']['status'], 'failed')
        output = StringIO()
        with redirect_stdout(output):
            guard_cli.show(task)
        self.assertIn('采集失败，本次未完成分析', output.getvalue())
        self.assertNotIn('未发现规则线索', output.getvalue())


if __name__ == '__main__':
    unittest.main()
