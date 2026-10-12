"""Launcher regressions: incomplete venv fallback and failure cleanup."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('winsec_dev', Path(__file__).resolve().parents[2] / 'dev.py')
dev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dev)


class LauncherTests(unittest.TestCase):
    def test_cli_launch_does_not_require_frontend(self):
        with patch.object(dev.sys, 'argv', ['dev.py', 'cli']), \
                patch.object(dev, 'select_python', return_value='python'), \
                patch.object(dev, 'check_backend'), \
                patch.object(dev, 'frontend_runtime') as frontend, \
                patch.object(dev.subprocess, 'call', return_value=0) as launch:
            self.assertEqual(dev.main(), 0)
            frontend.assert_not_called()
            self.assertIn('cli.py', launch.call_args.args[0][-1])

    def test_incomplete_environments_fall_back_to_working_interpreter(self):
        bad = subprocess.CompletedProcess([], 0, json.dumps({'supported': True, 'missing': ['fastapi']}))
        good = subprocess.CompletedProcess([], 0, json.dumps({'supported': True, 'missing': []}))
        with patch.object(Path, 'is_file', return_value=True), \
                patch.object(dev.subprocess, 'run', side_effect=[bad, bad, bad, good]):
            self.assertEqual(dev.select_python(), str(Path(dev.sys.executable).resolve()))

    def test_explicit_invalid_interpreter_does_not_silently_fall_back(self):
        with patch.object(Path, 'is_file', return_value=False):
            with self.assertRaises(RuntimeError):
                dev.select_python('missing-python.exe')

    def test_backend_failure_cleans_up_without_starting_frontend(self):
        process = Mock()
        with patch.object(dev.socket, 'socket'), \
                patch.object(dev.subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(dev, 'wait_ready', side_effect=RuntimeError('not ready')), \
                patch.object(dev, 'stop_process') as stop:
            with self.assertRaises(RuntimeError):
                dev.start('python', 'node', 'vite')
            self.assertEqual(spawn.call_count, 1)
            stop.assert_called_once_with(process)

    def test_occupied_port_does_not_start_any_process(self):
        sock = Mock()
        sock.bind.side_effect = OSError('busy')
        with patch.object(dev.socket, 'socket') as factory, patch.object(dev.subprocess, 'Popen') as spawn:
            factory.return_value.__enter__.return_value = sock
            with self.assertRaisesRegex(RuntimeError, '8000'):
                dev.start('python', 'node', 'vite')
            spawn.assert_not_called()

    def test_interrupt_stops_both_children_even_if_one_cleanup_fails(self):
        backend, frontend = Mock(), Mock()
        backend.poll.return_value = frontend.poll.return_value = None
        with patch.object(dev.socket, 'socket'), \
                patch.object(dev.subprocess, 'Popen', side_effect=[backend, frontend]), \
                patch.object(dev, 'wait_ready'), \
                patch.object(dev, 'stop_requested', return_value=False), \
                patch.object(dev.time, 'sleep', side_effect=KeyboardInterrupt), \
                patch.object(dev, 'stop_process', side_effect=[OSError('cleanup error'), None]) as stop:
            with self.assertRaises(KeyboardInterrupt):
                dev.start('python', 'node', 'vite')
            self.assertEqual([call.args[0] for call in stop.call_args_list], [frontend, backend])
