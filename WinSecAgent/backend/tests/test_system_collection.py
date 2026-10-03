import subprocess
import sys
import unittest
from unittest.mock import patch

from app.services import multi_source


class NetworkCollectionTests(unittest.TestCase):
    def test_localized_header_bytes_do_not_break_pipe_decoding(self):
        # Use a real subprocess pipe with invalid UTF-8 bytes, not a mocked string.
        # Only replace the executable; retain the collector's decoding options.
        output = b'\x81\xfe\xa1 header\r\n  TCP  127.0.0.1:8000  0.0.0.0:0  LISTENING  123\r\n  UDP  [::]:5353  *:*  456\r\n'
        real_run = subprocess.run

        def fake_netstat(command, **kwargs):
            self.assertEqual(command, ['netstat', '-ano'])
            return real_run([sys.executable, '-c', f'import sys; sys.stdout.buffer.write({output!r})'], **kwargs)

        with patch.object(multi_source.platform, 'system', return_value='Windows'), \
                patch.object(multi_source.subprocess, 'run', side_effect=fake_netstat):
            rows = multi_source.collect_network_connections()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], {'type': 'network', 'protocol': 'TCP', 'local': '127.0.0.1:8000',
                                  'remote': '0.0.0.0:0', 'state': 'LISTENING', 'pid': '123'})
        self.assertEqual(rows[1]['local'], '[::]:5353')
        self.assertEqual(rows[1]['state'], '')
        self.assertEqual(rows[1]['pid'], '456')

    def test_missing_stdout_returns_explicit_failure(self):
        with patch.object(multi_source.platform, 'system', return_value='Windows'), \
                patch.object(multi_source.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, None)):
            with self.assertRaisesRegex(RuntimeError, '未返回可读取的输出'):
                multi_source.collect_network_connections()

    def test_command_failure_is_not_an_empty_success(self):
        with patch.object(multi_source.platform, 'system', return_value='Windows'), \
                patch.object(multi_source.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '')):
            with self.assertRaisesRegex(RuntimeError, '网络连接读取失败'):
                multi_source.collect_network_connections()

    def test_network_failure_preserves_other_collectors(self):
        with patch.object(multi_source, 'collect_processes', return_value=[{'pid': 123}]), \
                patch.object(multi_source, 'collect_network_connections', side_effect=RuntimeError('采集失败')), \
                patch.object(multi_source, 'collect_services', return_value=[]), \
                patch.object(multi_source, 'collect_scheduled_tasks', return_value=[]), \
                patch.object(multi_source, 'collect_registry_suspicious', return_value=[]):
            result = multi_source.collect_all()
        self.assertEqual(result['processes'], [{'pid': 123}])
        self.assertEqual(result['network_connections'], [])
        self.assertEqual(result['collection_errors'], {'network_connections': '采集失败'})
        self.assertTrue(result['warnings'][0].startswith('网络连接未成功读取'))
        self.assertFalse(result['is_mock'])
