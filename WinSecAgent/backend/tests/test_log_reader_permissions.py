import sys
import unittest
from unittest.mock import Mock, patch

from app.services.log_reader import _read_real_logs, read_windows_logs


XML = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>7045</EventID><Level>4</Level><Channel>System</Channel>
<EventRecordID>10</EventRecordID></System></Event>'''


class LogReaderPermissionsTests(unittest.TestCase):
    def api(self):
        module = Mock(EvtQueryReverseDirection=512, EvtRenderEventXml=1)
        module.EvtRender.return_value = XML
        return module

    def read(self, module, channels, limit=2, filtered=False):
        with patch.dict(sys.modules, {'win32evtlog': module}), \
             patch('app.services.log_reader.platform.system', return_value='Windows'), \
             patch('app.services.log_reader._reader_context', return_value={'account': 'test', 'elevated': False}):
            return read_windows_logs(channels, filtered, limit)

    def test_denied_channel_keeps_other_real_records(self):
        module, query, event = self.api(), Mock(), Mock()
        module.EvtQuery.side_effect = [OSError(5, 'Access denied'), query]
        module.EvtNext.side_effect = [[event], OSError(259, 'No more items')]
        result = self.read(module, ['Security', 'System'])
        self.assertEqual(result['read_status'], 'partial')
        self.assertFalse(result['is_mock'])
        self.assertEqual(result['total_raw'], 1)
        self.assertIn('OriginalXml', result['events'][0])
        self.assertEqual(result['channel_results'][0]['error_kind'], 'access_denied')
        self.assertEqual(result['channel_results'][0]['error_code'], 5)
        self.assertEqual(result['channel_results'][1]['status'], 'success')
        query.Close.assert_called_once()
        event.Close.assert_called_once()

    def test_empty_channel_is_success_not_permission_failure(self):
        module = self.api()
        module.EvtNext.side_effect = OSError(259, 'No more items')
        result = self.read(module, ['System'])
        self.assertEqual(result['read_status'], 'success')
        self.assertEqual(result['total_raw'], 0)
        self.assertEqual(result['warnings'], [])

    def test_empty_success_and_denial_still_report_partial(self):
        module = self.api()
        module.EvtQuery.side_effect = [OSError(5, 'Access denied'), Mock()]
        module.EvtNext.return_value = []
        result = self.read(module, ['Security', 'System'])
        self.assertEqual(result['read_status'], 'partial')
        self.assertEqual(result['total_raw'], 0)

    def test_missing_channel_is_not_access_denied(self):
        module = self.api()
        module.EvtQuery.side_effect = OSError(15007, 'Missing channel')
        result = self.read(module, ['Missing'])
        self.assertEqual(result['read_status'], 'failed')
        self.assertEqual(result['channel_results'][0]['error_kind'], 'channel_not_found')

    def test_render_failure_preserves_progress_and_closes_whole_batch(self):
        module, query = self.api(), Mock()
        events = [Mock(), Mock(), Mock()]
        module.EvtQuery.return_value = query
        module.EvtNext.return_value = events
        module.EvtRender.side_effect = [XML, ValueError('bad XML')]
        result = self.read(module, ['System'], limit=3)
        self.assertEqual(result['read_status'], 'partial')
        self.assertEqual(result['channel_results'][0]['events_read'], 1)
        self.assertEqual(result['channel_results'][0]['error_kind'], 'read_error')
        self.assertEqual(result['total_raw'], 1)
        for event in events:
            event.Close.assert_called_once()
        query.Close.assert_called_once()

    def test_filter_does_not_change_channel_read_count(self):
        module = self.api()
        module.EvtNext.return_value = [Mock()]
        module.EvtRender.return_value = XML.replace('7045', '1')
        result = self.read(module, ['System'], limit=1, filtered=True)
        self.assertEqual(result['read_status'], 'success')
        self.assertEqual(result['total_raw'], 1)
        self.assertEqual(result['total_filtered'], 0)
        self.assertEqual(result['channel_results'][0]['events_read'], 1)

    def test_missing_dependency_never_generates_demo_events_on_windows(self):
        with patch.dict(sys.modules, {'win32evtlog': None}):
            events, statuses = _read_real_logs(['Security'])
        self.assertEqual(events, [])
        self.assertEqual(statuses[0]['error_kind'], 'dependency_missing')


if __name__ == '__main__':
    unittest.main()
