"""Interactive navigation regressions; no live model requests or host changes."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import guard
import guard_cli
import guard_models
import terminal_ui


class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'backend/data')
        self.addCleanup(self.temp.cleanup)
        self.profiles = guard_models.Profiles(Path(self.temp.name) / 'models.json')

    def configure(self, answers, models=None):
        output = io.StringIO()
        with patch('builtins.input', side_effect=answers), redirect_stdout(output), \
                patch('terminal_ui.getpass.getpass', return_value='test-session-secret'), \
                patch('guard_cli.discover', return_value=models or ['model-a', 'model-b']) as discover:
            guard_cli.configure(self.profiles)
        return output.getvalue(), discover

    def test_deepseek_preset_list_selection_and_secret_never_saved_or_printed(self):
        output, discover = self.configure(['2', '', '', '', '2', '', ''])
        name, profile = self.profiles.active()
        self.assertEqual((name, profile['kind'], profile['base_url'], profile['model']),
                         ('deepseek', 'openai', 'https://api.deepseek.com', 'model-b'))
        self.assertEqual(self.profiles.key(name, profile), 'test-session-secret')
        self.assertNotIn('test-session-secret', self.profiles.path.read_text(encoding='utf-8') + output)
        self.assertEqual(discover.call_args.args[1], 'test-session-secret')

    def test_invalid_url_retries_only_that_field_and_can_cancel_without_writing(self):
        output, discover = self.configure(['1', 'bad-url', '0'])
        self.assertIn('请修改这一项', output)
        self.assertFalse(self.profiles.path.exists())
        discover.assert_not_called()

    def test_cancel_at_each_step_preserves_existing_profile_and_session_key(self):
        self.profiles.put('ollama', dict(kind='ollama', base_url='http://localhost:11434', model='old'), 'original')
        original = self.profiles.path.read_bytes()
        # Add configuration, service, base, model method, model, name, final confirmation.
        flow = ['1', '1', '', '2', 'new', '', '1']
        for index in range(len(flow)):
            with self.subTest(index=index):
                self.configure(flow[:index] + ['0'])
                self.assertEqual(self.profiles.path.read_bytes(), original)
                self.assertEqual(self.profiles.session_keys, {'ollama': 'original'})

    def test_failed_discovery_can_switch_to_manual_without_reentering_address(self):
        with patch('builtins.input', side_effect=['1', '', '', '2', 'local-model', '', '']), \
                patch('guard_cli.discover', side_effect=RuntimeError('服务未启动')), redirect_stdout(io.StringIO()):
            guard_cli.configure(self.profiles)
        self.assertEqual(self.profiles.active()[1]['model'], 'local-model')

    def test_profile_switch_uses_list_number(self):
        for name in ('local', 'remote'):
            self.profiles.put(name, dict(kind='ollama', base_url='http://localhost:11434', model=name))
        self.configure(['2', '1'])
        self.assertEqual(self.profiles.active()[0], 'local')

    def test_ctrl_c_during_model_discovery_returns_without_saving(self):
        with patch('builtins.input', side_effect=['1', '', '']), \
                patch('guard_cli.discover', side_effect=KeyboardInterrupt), redirect_stdout(io.StringIO()):
            guard_cli.configure(self.profiles)
        self.assertFalse(self.profiles.path.exists())

    def test_wizard_corrects_invalid_protection_before_collecting_and_opens_result(self):
        store = guard.TaskStore(Path(self.temp.name) / 'tasks.db')
        with patch('builtins.input', side_effect=['3', 'not-an-ip', '', '0']), \
                patch('guard_cli.demo_events', return_value=guard.demo_events('linux')) as collect, \
                redirect_stdout(io.StringIO()) as output:
            guard_cli.wizard(store, self.profiles)
        collect.assert_called_once()
        self.assertEqual(len(store.recent()), 1)
        self.assertIn('请修改这一项', output.getvalue())
        self.assertIn('模拟分析完成', output.getvalue())

    def test_tasks_open_by_number_and_return_to_list_after_details(self):
        store = guard.TaskStore(Path(self.temp.name) / 'tasks.db')
        task = guard.run_task(store, 'demo:linux', lambda: guard.demo_events('linux'), demo=True)
        output = io.StringIO()
        with patch('builtins.input', side_effect=['1', '2', '0', '0']), redirect_stdout(output):
            guard_cli.task_menu(store, self.profiles)
        self.assertIn(task['events'][0]['ref'], output.getvalue())
        self.assertGreaterEqual(output.getvalue().count('防护任务历史'), 2)

    def test_chat_failure_keeps_task_open_for_retry(self):
        store = guard.TaskStore(Path(self.temp.name) / 'tasks.db')
        task = guard.run_task(store, 'demo:linux', lambda: guard.demo_events('linux'), demo=True)
        self.profiles.put('local', dict(kind='ollama', base_url='http://localhost:11434', model='local'))
        with patch('builtins.input', side_effect=['解释一下', '再试一次', '0']), \
                patch('guard_cli.ask', side_effect=[RuntimeError('连接失败'), '成功回答']) as ask, \
                redirect_stdout(io.StringIO()) as output:
            guard_cli.chat(store, self.profiles, task['id'])
        self.assertEqual(ask.call_count, 2)
        self.assertIn('成功回答', output.getvalue())

    def test_discovery_get_only_bounded_and_no_redirects(self):
        response = Mock(status_code=200)
        response.iter_content.return_value = [json.dumps({'data': [{'id': 'm1'}, {'id': 'm1'}, {'id': 'm2'}]}).encode()]
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        profile = dict(kind='openai', base_url='https://example.com/v1', model='')
        with patch('requests.get', return_value=response) as get:
            self.assertEqual(guard_models.discover(profile, 'secret'), ['m1', 'm2'])
        self.assertEqual(get.call_args.args[0], 'https://example.com/v1/models')
        self.assertFalse(get.call_args.kwargs['allow_redirects'])
        self.assertNotIn('json', get.call_args.kwargs)
        response.iter_content.return_value = [b'x' * (1024 * 1024 + 1)]
        with patch('requests.get', return_value=response), self.assertRaisesRegex(RuntimeError, '过大'):
            guard_models.discover(profile)

    def test_hidden_input_failure_never_falls_back_to_echoing_key(self):
        import warnings
        def fallback(*args):
            warnings.warn('no tty', terminal_ui.getpass.GetPassWarning)
            self.fail('must stop before visible input')
        with patch('terminal_ui.getpass.getpass', side_effect=fallback), \
                self.assertRaisesRegex(ValueError, '无法隐藏'):
            terminal_ui.read_line('key: ', secret=True)

    def test_backspace_fallback_and_ctrl_c_cancel(self):
        self.assertEqual(terminal_ui.clean_input('12\b3\x7f4'), '14')
        with patch('builtins.input', side_effect=KeyboardInterrupt), redirect_stdout(io.StringIO()), \
                self.assertRaises(terminal_ui.Cancelled):
            terminal_ui.field('地址')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux PTY verifies real readline editing')
    def test_linux_pty_accepts_both_xshell_backspace_codes(self):
        import pty
        import select
        for key in (b'\x08', b'\x7f'):
            with self.subTest(key=key):
                master, slave = pty.openpty()
                script = "from terminal_ui import setup_terminal; setup_terminal(); print('RESULT=' + input('READY> '), flush=True)"
                proc = subprocess.Popen([sys.executable, '-c', script], cwd=ROOT,
                                        stdin=slave, stdout=slave, stderr=slave, close_fds=True)
                os.close(slave)
                output = b''
                sent = False
                try:
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        if select.select([master], [], [], 0.1)[0]:
                            try:
                                chunk = os.read(master, 4096)
                            except OSError:
                                break
                            if not chunk:
                                break
                            output += chunk
                            if b'READY> ' in output and not sent:
                                os.write(master, b'12' + key + b'3\n')
                                sent = True
                        if b'RESULT=' in output:
                            break
                    self.assertIn(b'RESULT=13', output)
                    self.assertEqual(proc.wait(timeout=5), 0)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
                    os.close(master)


if __name__ == '__main__':
    unittest.main()
