"""Check the separate Linux export workflow using disposable log files."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from server_logs import analyze_directory, render_report, render_console

TEST_DATA = ROOT / "backend" / "data"


class ServerLogTests(unittest.TestCase):
    def make_export(self, directory: Path) -> None:
        ssh = [
            f"2026-10-12T10:0{i}:00+08:00 host sshd[1]: Failed password for root from 192.0.2.10 port 5000 ssh2"
            for i in range(5)
        ]
        ssh.append("2026-10-12T10:06:00+08:00 host sshd[1]: Accepted password for root from 192.0.2.10 port 5001 ssh2")
        (directory / "ssh.journal.log").write_text("\n".join(ssh) + "\n", encoding="utf-8")
        requests = [
            {"occurred_at": "2026-10-12T10:07:00+08:00", "client_ip": "192.0.2.10",
             "method": "POST", "path": "/api/auth/login", "status_code": 500,
             "service": "candidate-api", "server_host": "host",
             "request_id": "request-1", "duration_seconds": 0.01},
            {"occurred_at": "2026-10-12T10:08:00+08:00", "client_ip": "192.0.2.11",
             "method": "GET", "path": "/.env", "status_code": 404, "request_id": ""},
        ]
        (directory / "nginx-security-access.log").write_text(
            "\n".join(json.dumps(item) for item in requests) + "\n", encoding="utf-8")
        exception = {"occurred_at": "2026-10-12T02:07:00Z", "event_type": "http.exception",
                     "request_id": "request-1", "error_type": "pymysql.err.OperationalError",
                     "status_code": 500, "service": "candidate-api"}
        (directory / "candidate-api.journal.log").write_text(
            "2026-10-12T10:07:00+08:00 host uvicorn[2]: " + json.dumps(exception) + "\n"
            "2026-10-12T10:09:00+08:00 host systemd[1]: Stopping ai-interview-backend.service - Backend\n"
            "2026-10-12T10:09:02+08:00 host uvicorn[2]: pymysql.err.OperationalError: (1213, 'Deadlock found')\n"
            "2026-10-12T10:09:03+08:00 host systemd[1]: ai-interview-backend.service: Main process exited\n"
            "2026-10-12T10:09:05+08:00 host systemd[1]: Started ai-interview-backend.service - Backend\n", encoding="utf-8")
        names = ("ssh.journal.log", "nginx-security-access.log", "candidate-api.journal.log")
        (directory / "SHA256SUMS.txt").write_text("\n".join(
            f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()} *{name}" for name in names
        ) + "\n", encoding="utf-8")

    def test_correlates_ssh_success_and_http_failure_without_modifying_source(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as temporary:
            directory = Path(temporary)
            self.make_export(directory)
            before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir()}
            result = analyze_directory(directory)
            self.assertEqual(result["ssh"]["failed"], 5)
            self.assertEqual(result["ssh"]["root_password_success"], 1)
            self.assertEqual(result["ssh"]["success_after_failures"][0]["failure_count"], 5)
            self.assertEqual(result["nginx"]["five_xx"][0]["app_exception"]["error_type"], "pymysql.err.OperationalError")
            self.assertEqual(result["nginx"]["probe_count"], 1)
            self.assertEqual(result["application"]["startup_errors"][0]["code"], "1213")
            self.assertEqual(len(result["application"]["nearby_root_logins"]), 1)
            self.assertTrue(all(item["status"] == "match" for item in result["checks"]))
            self.assertIn("非 JSON 文本行", " ".join(result["warnings"]))
            self.assertIn("root 密码登录成功", render_report(result))
            self.assertIn("仅时间关联", render_report(result))
            after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir()}
            self.assertEqual(before, after)

    def test_cli_saves_quoted_report_path_without_database(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as temporary:
            directory = Path(temporary)
            source = directory / "source"
            source.mkdir()
            self.make_export(source)
            output = directory / "report"
            run = subprocess.run(
                [sys.executable, "-X", "utf8", str(ROOT / "cli.py"), "server", str(source),
                 "--output", f'"{output}"'], capture_output=True, text=True, encoding="utf-8", timeout=30,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("SSH：5 次密码失败", run.stdout)
            self.assertTrue(output.with_suffix(".md").is_file())
            forbidden = source / "report.md"
            blocked = subprocess.run(
                [sys.executable, "-X", "utf8", str(ROOT / "cli.py"), "server", str(source),
                 "--output", str(forbidden)], capture_output=True, text=True, encoding="utf-8", timeout=30,
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertFalse(forbidden.exists())
            menu_report = directory / "menu-report"
            menu = subprocess.run(
                [sys.executable, "-X", "utf8", str(ROOT / "cli.py"), "--database", str(directory / "menu.db")],
                input=f'7\n"{source}"\n"{menu_report}"\n0\n', capture_output=True, text=True,
                encoding="utf-8", timeout=30,
            )
            self.assertEqual(menu.returncode, 0, menu.stderr)
            self.assertNotIn("操作失败", menu.stdout)
            self.assertIn("任务已开始", menu.stdout)
            self.assertIn("报告已保存", menu.stdout)
            self.assertTrue(menu_report.with_suffix(".md").is_file())

    def test_coverage_balances_lines_and_exposes_unknown_and_invalid_data(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as temporary:
            root = Path(temporary)
            good = '2026-10-12T10:00:00+08:00 host sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2'
            (root / 'ssh.journal.log').write_text(good + '\n' + good + '\n\nunknown text\n', encoding='utf-8')
            (root / 'nginx-security-access.log').write_text('{bad\n' + json.dumps({'status_code': 900}) + '\n', encoding='utf-8')
            (root / 'candidate-api.journal.log').write_text('{broken\n', encoding='utf-8')
            (root / 'mysql-error.log').write_text('', encoding='utf-8')
            (root / 'extra.log').write_text('unsupported', encoding='utf-8')
            result = analyze_directory(root)
            q = result['quality']
            self.assertEqual((q['discovered'], q['recognized'], q['lines']), (5, 4, 7))
            self.assertEqual((q['parsed'], q['unparsed'], q['invalid'], q['duplicates'], q['blank']), (1, 1, 3, 1, 1))
            for info in result['files'].values():
                self.assertEqual(info['lines'], sum(info[k] for k in ('parsed', 'unparsed', 'invalid', 'duplicates', 'blank')))
            self.assertEqual(result['ssh']['failed'], 1)
            self.assertEqual(result['time_range']['start'], '2026-10-12T02:00:00+00:00')
            self.assertEqual(result['files']['mysql-error.log']['status'], 'empty')
            self.assertEqual(q['ignored_files'], ['extra.log'])
            self.assertIn('candidate-api.journal.log:1', render_report(result))
            self.assertIn('格式无效 3 行', render_console(result))

    def test_oversized_file_is_skipped_without_claiming_empty_or_blocking_other_sources(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as temporary:
            root = Path(temporary)
            (root / 'ssh.journal.log').write_text('x' * 100, encoding='utf-8')
            (root / 'nginx-security-access.log').write_text('{bad\n', encoding='utf-8')
            with patch('server_logs.MAX_FILE_BYTES', 50):
                result = analyze_directory(root)
            self.assertEqual(result['files']['ssh.journal.log']['status'], 'skipped_large')
            self.assertEqual(result['quality']['skipped_large'], 1)
            self.assertEqual(result['quality']['invalid'], 1)
            self.assertIn('无法判断', result['assessment'])
            self.assertIn('跳过行数未知', render_report(result))

    def test_ssh_requires_same_host_account_ip_time_and_sorts_evidence(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as temporary:
            root = Path(temporary)
            lines = [
                '2026-10-12T10:29:00+08:00 host sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2',
                '2026-10-12T10:00:00+08:00 host sshd[1]: Failed password for root from 192.0.2.1 port 2 ssh2',
                '2026-10-12T09:59:59+08:00 host sshd[1]: Failed password for root from 192.0.2.1 port 3 ssh2',
                '2026-10-12T10:29:00+08:00 other sshd[1]: Failed password for root from 192.0.2.1 port 4 ssh2',
                '2026-10-12T10:29:00+08:00 host sshd[1]: Failed password for admin from 192.0.2.1 port 5 ssh2',
                '2026-10-12T10:29:00+08:00 host sshd[1]: Failed password for root from 192.0.2.2 port 6 ssh2',
                '2026-10-12T10:29:00 host sshd[1]: Failed password for root from 192.0.2.1 port 7 ssh2',
                '2026-10-12T02:30:00Z host sshd[1]: Accepted password for root from 192.0.2.1 port 8 ssh2',
            ]
            (root / 'ssh.journal.log').write_text('\n'.join(lines + [lines[0]]) + '\n', encoding='utf-8')
            result = analyze_directory(root)
            self.assertEqual(len(result['ssh']['success_after_failures']), 1)
            finding = result['ssh']['success_after_failures'][0]
            self.assertEqual(finding['failure_count'], 2)
            self.assertEqual(finding['first_failure'], 'ssh.journal.log:2')
            self.assertEqual(result['ssh']['correlation_excluded'], 1)

    def http_result(self, root, requests, exceptions):
        (root / 'nginx-security-access.log').write_text('\n'.join(json.dumps(r) for r in requests) + '\n', encoding='utf-8')
        (root / 'candidate-api.journal.log').write_text('\n'.join(json.dumps(r) for r in exceptions) + '\n', encoding='utf-8')
        return analyze_directory(root)

    def test_http_reused_id_keeps_candidates_and_requires_scope_and_time(self):
        request = dict(occurred_at='2026-10-12T10:00:00+08:00', status_code=500, request_id='same',
                       service='api', server_host='host', method='GET', path='/items')
        exception = dict(occurred_at='2026-10-12T02:00:00Z', event_type='http.exception', request_id='same',
                         service='api', server_host='host', method='GET', route='/items', error_type='First')
        cases = [
            ('unique', request, [exception], 1, True),
            ('duplicate text', request, [exception, exception], 1, True),
            ('ambiguous', request, [exception, {**exception, 'error_type': 'Second'}], 2, False),
            ('other service', request, [{**exception, 'service': 'other'}], 0, False),
            ('other host', request, [{**exception, 'server_host': 'other'}], 0, False),
            ('other route', request, [{**exception, 'route': '/other'}], 0, False),
            ('other method', request, [{**exception, 'method': 'POST'}], 0, False),
            ('no service', {**request, 'service': ''}, [exception], 1, False),
            ('exception has no service', request, [{**exception, 'service': ''}], 0, False),
            ('no host', {**request, 'server_host': ''}, [exception], 1, False),
            ('no timestamp', request, [{**exception, 'occurred_at': ''}], 0, False),
            ('naive time', {**request, 'occurred_at': '2026-10-12T10:00:00'}, [exception], 0, False),
            ('window boundary', request, [{**exception, 'occurred_at': '2026-10-12T02:02:00Z'}], 1, True),
            ('outside window', request, [{**exception, 'occurred_at': '2026-10-12T02:02:01Z'}], 0, False),
        ]
        for name, req, errors, count, matched in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=TEST_DATA) as temporary:
                result = self.http_result(Path(temporary), [req], errors)
                item = result['nginx']['five_xx'][0]
                self.assertEqual(len(item['app_candidates']), count)
                self.assertEqual(bool(item['app_exception']), matched)
                self.assertIn(item['correlation_status'], render_report(result))

    def test_http_same_exception_for_multiple_requests_is_not_unique(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as temporary:
            request = dict(occurred_at='2026-10-12T02:00:00Z', status_code=500, request_id='same', service='api', server_host='host')
            exception = dict(occurred_at='2026-10-12T02:00:00Z', event_type='http.exception', request_id='same', service='api', server_host='host')
            result = self.http_result(Path(temporary), [request, {**request, 'occurred_at': '2026-10-12T02:00:01Z'}], [exception])
            self.assertTrue(all(item['app_exception'] is None for item in result['nginx']['five_xx']))

    def test_empty_sources_and_unrecognized_only_are_insufficient(self):
        for content in ('', 'unrecognized text\n', '\n'):
            with self.subTest(content=content), tempfile.TemporaryDirectory(dir=TEST_DATA) as temporary:
                root = Path(temporary)
                (root / 'ssh.journal.log').write_text(content, encoding='utf-8')
                result = analyze_directory(root)
                self.assertIn('无法判断', result['assessment'])
                self.assertIsNone(result['time_range']['start'])

    def test_root_login_cannot_link_to_another_hosts_service_stop(self):
        with tempfile.TemporaryDirectory(dir=TEST_DATA) as temporary:
            root = Path(temporary)
            self.make_export(root)
            app = root / 'candidate-api.journal.log'
            app.write_text(app.read_text(encoding='utf-8').replace('host systemd', 'other systemd'), encoding='utf-8')
            result = analyze_directory(root)
            self.assertEqual(result['application']['nearby_root_logins'], [])
            self.assertTrue(any(c['status'] == 'mismatch' for c in result['checks']))


if __name__ == "__main__":
    unittest.main()
