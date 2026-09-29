import json
import unittest
from unittest.mock import Mock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.agents.event_context import extract_event_context, serialize_windows_event
from app.agents.parser_agent import parse_alert, _fallback_parse
from app.agents.evidence_agent import gather_evidence
from app.agents.response_agent import _fallback_actions
from app.agents.report_agent import generate_report
from app.cases.demo_cases import DEMO_CASES
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app import models


class SourceTests(unittest.TestCase):
    def test_windows_json_preserves_fields(self):
        parsed = parse_alert(DEMO_CASES[0]['raw_content'])
        self.assertEqual((parsed['platform'], parsed['event_id'], parsed['username']), ('Windows', '4625', 'lab_admin'))
        self.assertEqual(parsed['computer'], 'WIN-LAB-01')
        self.assertEqual(parsed['source_ip'], '192.0.2.10')
        self.assertTrue(parsed['is_demo'])
        self.assertIsNone(parsed['target_port'])

    def test_event_viewer_xml(self):
        raw = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4648</EventID><TimeCreated SystemTime="2026-09-29T02:15:00Z"/><Channel>Security</Channel><Computer>WIN-02</Computer></System><EventData><Data Name="TargetUserName">svc_backup</Data><Data Name="IpAddress">192.0.2.9</Data></EventData></Event>'''
        parsed = parse_alert(raw)
        self.assertEqual(parsed['event_id'], '4648')
        self.assertEqual(parsed['username'], 'svc_backup')
        self.assertEqual(parsed['computer'], 'WIN-02')
        self.assertIsNone(parsed['target_port'])

    def test_manual_envelope_preserves_embedded_json(self):
        raw = serialize_windows_event({'OriginalLog': DEMO_CASES[0]['raw_content'], 'Computer': 'OVERRIDE'}, True)
        parsed = parse_alert(raw)
        self.assertEqual(parsed['event_id'], '4625')
        self.assertEqual(parsed['computer'], 'OVERRIDE')
        self.assertEqual(parsed['username'], 'lab_admin')

    def test_timestamp_is_not_port_and_chinese_username(self):
        parsed = _fallback_parse('Source: 192.0.2.10\nTarget: 198.51.100.20\nTime: 2026-09-29T03:15:00Z\n用户名为 root。\nProcess: /tmp/example')
        self.assertIsNone(parsed['target_port'])
        self.assertEqual(parsed['username'], 'root')
        self.assertEqual(parsed['platform'], 'Linux')
        self.assertEqual(_fallback_parse('Target: host (198.51.100.20:3389)')['target_port'], 3389)

    def test_unknown_platform_stays_unknown(self):
        self.assertEqual(extract_event_context('login failed')['platform'], 'Unknown')

    def test_evidence_does_not_invent_asset_or_ioc(self):
        raw = DEMO_CASES[0]['raw_content']
        evidence = gather_evidence(parse_alert(raw), raw)
        text = json.dumps(evidence, ensure_ascii=False)
        self.assertNotIn('CentOS', text)
        self.assertNotIn('Mirai', text)
        self.assertNotIn('CVE-2021-44228', text)
        self.assertEqual(evidence[0]['content'], raw)
        self.assertEqual(evidence[0]['source'], 'demo_input')

    def test_windows_fallback_actions(self):
        parsed = parse_alert(DEMO_CASES[0]['raw_content'])
        text = json.dumps(_fallback_actions(parsed, DEMO_CASES[0]['raw_content']), ensure_ascii=False)
        self.assertIn('Windows', text)
        self.assertNotIn('None', text)
        self.assertNotIn('kill -9', text)

    def test_all_examples_are_windows(self):
        for case in DEMO_CASES:
            self.assertEqual(parse_alert(case['raw_content'])['platform'], 'Windows')

    def test_report_is_complete_without_an_independent_model_verdict(self):
        raw = DEMO_CASES[0]['raw_content']
        parsed = parse_alert(raw)
        report = generate_report('测试', parsed, {}, gather_evidence(parsed, raw), {}, [])
        self.assertIn('## 6. 复盘建议', report)
        self.assertIn('目标平台：Windows', report)
        self.assertIn('演示日志', report)
        self.assertIn('结构化报告', report)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine)()
        app.dependency_overrides[get_db] = lambda: self.session
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.session.close()
        self.engine.dispose()

    def test_cases_and_manual_validation(self):
        cases = self.client.get('/api/alerts/cases').json()
        self.assertEqual(len(cases), 5)
        self.assertTrue(all(c['id'].startswith('windows_') for c in cases))
        bad = self.client.post('/api/alerts', json={'title':'空', 'raw_content':' ', 'windows_context':{}})
        self.assertEqual(bad.status_code, 422)
        wrong = self.client.post('/api/alerts', json={'title':'错误平台','raw_content':'Platform: Linux\nHost: Ubuntu','windows_context':{}})
        self.assertEqual(wrong.status_code, 422)

    def test_recovery_retains_original_record(self):
        from app.services.recovery import recover_interrupted_analyses
        alert = models.Alert(title='恢复测试', raw_content='original')
        self.session.add(alert)
        self.session.flush()
        incident = models.Incident(alert_id=alert.id, status='analyzing')
        self.session.add(incident)
        self.session.commit()
        self.assertEqual(recover_interrupted_analyses(self.session), 1)
        self.assertEqual(incident.status, 'interrupted')
        self.assertEqual(incident.alert.raw_content, 'original')

    def test_manual_creation_and_report_regeneration_keep_platform(self):
        created = self.client.post('/api/alerts', json={'title':'Windows 测试','raw_content':DEMO_CASES[0]['raw_content'],'windows_context':{}})
        self.assertEqual(created.status_code, 200)
        incident = self.client.post('/api/incidents', json={'alert_id':created.json()['id']}).json()
        with patch('app.agents.report_agent.generate_report', return_value='Windows report') as generate:
            response = self.client.post(f"/api/incidents/{incident['id']}/report")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(generate.call_args.kwargs['parsed']['platform'], 'Windows')
        self.assertEqual(generate.call_args.kwargs['parsed']['event_id'], '4625')
        download = self.client.get(f"/api/reports/{response.json()['id']}/download")
        self.assertIn('目标平台：Windows', download.text)
        self.assertIn('证据不足', download.text)
        self.assertIn('attachment', download.headers['content-disposition'])

    def test_import_preserves_event_metadata(self):
        event = {'EventID':4625,'Channel':'Security','Computer':'WIN-API','Message':'失败登录','TimeCreated':'2026-09-29T02:00:00Z','EventData':{'TargetUserName':'user1'}}
        with patch('app.api.logs.read_windows_logs', return_value={'events':[event],'is_mock':False,'total_filtered':1}):
            response = self.client.post('/api/logs/import', json={})
        self.assertEqual(response.status_code, 200)
        parsed = parse_alert(self.session.query(models.Alert).first().raw_content)
        self.assertEqual(parsed['computer'], 'WIN-API')
        self.assertEqual(parsed['username'], 'user1')

    def test_windows_report_does_not_reuse_old_linux_actions(self):
        alert = models.Alert(title='Windows', raw_content=DEMO_CASES[1]['raw_content'])
        self.session.add(alert)
        self.session.flush()
        incident = models.Incident(alert_id=alert.id)
        self.session.add(incident)
        self.session.flush()
        self.session.add(models.ResponseAction(incident_id=incident.id, action_type='old', description='kill -9 123', risk='high', approval_required=True))
        self.session.commit()
        with patch('app.agents.report_agent.generate_report', return_value='Windows report') as generate:
            self.client.post(f'/api/incidents/{incident.id}/report')
        actions = generate.call_args.kwargs['actions']
        self.assertNotIn('kill -9', json.dumps(actions))
        self.assertIn('Windows', actions[0]['description'])

    def test_channel_failure_is_visible_not_mock(self):
        failure = {'channel': 'Security', 'status': 'failed', 'events_read': 0,
                   'error_kind': 'access_denied', 'error_code': 5, 'message': 'Security 日志读取权限不足。'}
        with patch('app.services.log_reader.platform.system', return_value='Windows'), patch('app.services.log_reader._read_real_logs', return_value=([], [failure])):
            response = self.client.post('/api/logs/read', json={}).json()
        self.assertFalse(response['is_mock'])
        self.assertEqual(response['events'], [])
        self.assertIn('Security', response['warnings'][0])
        self.assertEqual(response['read_status'], 'failed')
        self.assertEqual(response['channel_results'][0]['error_code'], 5)

    def test_system_failure_never_becomes_sample_process(self):
        from app.services.multi_source import collect_all
        with patch('app.services.multi_source.collect_processes', side_effect=RuntimeError('denied')), patch('app.services.multi_source.collect_network_connections', return_value=[]), patch('app.services.multi_source.collect_services', return_value=[]), patch('app.services.multi_source.collect_scheduled_tasks', return_value=[]), patch('app.services.multi_source.collect_registry_suspicious', return_value=[]):
            result = collect_all()
        self.assertFalse(result['is_mock'])
        self.assertEqual(result['processes'], [])
        self.assertTrue(result['warnings'])


if __name__ == '__main__':
    unittest.main()
