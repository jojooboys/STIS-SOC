"""Uji kesesuaian payload endpoint dan perilaku antarmuka dengan SQLite memory."""

import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from app import create_app
from app.extensions import db
from app.models import Alert, AuditLog, BlockedIP, User
from app.services.response_engine import ResponseEngine
from app.services.pfsense_service import PfSenseService
from app.utils.helpers import set_setting


class UIAPIContractTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_scheduler=False)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()

        user = User(username='test-admin')
        user.set_password('test-only')
        db.session.add(user)
        db.session.commit()

        self.client = self.app.test_client()
        response = self.client.post('/api/auth/login', json={
            'username': 'test-admin', 'password': 'test-only'
        })
        self.assertEqual(response.status_code, 200)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def test_audit_endpoint_orders_by_created_at_and_returns_items(self):
        response = self.client.get('/api/audit?per_page=25')
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json['total'], 1)
        self.assertIn('created_at', response.json['items'][0])
        self.assertIn('performed_by', response.json['items'][0])
        self.assertIn('result', response.json['items'][0])

    def test_block_endpoint_passes_canonical_payload_to_engine(self):
        with patch.object(ResponseEngine, 'manual_block', return_value={
            'status': 'success', 'message': 'Successfully blocked 198.51.100.2'
        }) as manual_block:
            response = self.client.post('/api/blocked-ips', json={
                'ip_address': '198.51.100.2',
                'reason': 'Integration test',
            })

        self.assertEqual(response.status_code, 201)
        manual_block.assert_called_once_with(
            '198.51.100.2', 'Integration test', 'test-admin'
        )

    def test_block_endpoint_rejects_old_nested_frontend_payload(self):
        response = self.client.post('/api/blocked-ips', json={
            'ip_address': {'ip': '198.51.100.2', 'reason': 'Integration test'}
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['message'], 'IP address and reason are required')

    def test_pfsense_failure_is_returned_and_written_to_audit_log(self):
        engine = ResponseEngine()
        engine._pfsense_service = Mock()
        engine._pfsense_service.block_ip.return_value = {
            'status': 'error', 'message': '403 Client Error - missing alias PATCH privilege'
        }

        result = engine.manual_block(
            '198.51.100.3', 'Permission test', 'test-admin'
        )

        self.assertEqual(result['status'], 'error')
        self.assertIn('403 Client Error', result['message'])
        log = AuditLog.query.filter_by(action='block_ip').order_by(AuditLog.id.desc()).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.result, 'failure')
        self.assertIn('403 Client Error', log.error_message)

    def test_reblock_persists_and_selected_history_deletes_only_unblocked(self):
        record = BlockedIP(ip_address='198.51.100.4', reason='Test', source='manual',
                           status='unblocked', blocked_by='test-admin')
        db.session.add(record)
        db.session.commit()
        record_id = record.id
        with patch.object(PfSenseService, 'block_ip', return_value={'status': 'success'}):
            response = self.client.post(f'/api/blocked-ips/{record_id}/reblock')
        self.assertEqual(response.status_code, 200)
        db.session.expire_all()
        self.assertEqual(db.session.get(BlockedIP, record_id).status, 'blocked')
        self.assertEqual(self.client.delete('/api/blocked-ips/history', json={'ids': [record_id]}).status_code, 400)
        with patch.object(PfSenseService, 'unblock_ip', return_value={'status': 'success'}):
            self.assertEqual(self.client.delete(f'/api/blocked-ips/{record_id}').status_code, 200)
        response = self.client.delete('/api/blocked-ips/history', json={'ids': [record_id]})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(db.session.get(BlockedIP, record_id))

    def test_sync_reconciles_seed_rows_and_rejects_api_failure(self):
        old = BlockedIP(ip_address='198.51.100.5', reason='Seed', status='blocked')
        db.session.add(old)
        db.session.commit()
        with patch.object(PfSenseService, 'read_blocklist', return_value={
            'status': 'error', 'message': '403 Forbidden'
        }):
            response = self.client.post('/api/blocked-ips/sync')
        self.assertEqual(response.status_code, 502)
        self.assertEqual(db.session.get(BlockedIP, old.id).status, 'blocked')
        with patch.object(PfSenseService, 'read_blocklist', return_value={
            'status': 'success', 'addresses': ['198.51.100.6']
        }):
            response = self.client.post('/api/blocked-ips/sync')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['marked_unblocked'], 1)
        self.assertEqual(response.json['imported'], 1)
        self.assertEqual(db.session.get(BlockedIP, old.id).status, 'unblocked')
        self.assertEqual(BlockedIP.query.filter_by(ip_address='198.51.100.6').first().status, 'blocked')

    def test_auto_block_fresh_alert_and_explain_gateway_skip(self):
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')
        engine = ResponseEngine()
        template = {
            'alert_id': 'test-alert-1', 'timestamp': datetime.now(timezone.utc).isoformat(),
            'rule_id': '31151', 'rule_level': 10, 'rule_description': 'HTTP errors',
            'rule_groups': '[]', 'agent_id': '001', 'agent_name': 'web',
            'src_ip': '10.10.10.1', 'dst_ip': None, 'src_port': None, 'dst_port': 80,
            'full_log': '', 'raw_json': '{}',
        }
        self.assertEqual(engine.evaluate_threat(template)['action'], 'whitelisted')
        template['src_ip'] = '192.168.18.53'
        engine._pfsense_service = Mock()
        engine._pfsense_service.block_ip.return_value = {'status': 'success'}
        summary = engine.process_alerts([template])
        self.assertEqual(summary['blocked'], 1)
        self.assertEqual(Alert.query.filter_by(alert_id='test-alert-1').first().action_taken, 'blocked')
        self.assertEqual(BlockedIP.query.filter_by(ip_address='192.168.18.53', status='blocked').count(), 1)

    def test_recent_alert_deferred_while_disabled_is_reprocessed_after_enable(self):
        deferred = Alert(
            alert_id='deferred-1', timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=100102, rule_level=10, rule_description='Web brute force',
            rule_groups='[]', agent_id='001', agent_name='web',
            src_ip='192.168.18.53', raw_json='{}', is_processed=True,
            action_taken='disabled',
        )
        db.session.add(deferred)
        db.session.commit()
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')

        engine = ResponseEngine()
        engine._pfsense_service = Mock()
        engine._pfsense_service.block_ip.return_value = {'status': 'success'}
        summary = engine.reprocess_recent_alerts()

        self.assertEqual(summary['blocked'], 1)
        self.assertEqual(db.session.get(Alert, deferred.id).action_taken, 'blocked')
        self.assertEqual(BlockedIP.query.filter_by(ip_address='192.168.18.53', status='blocked').count(), 1)

    def test_wazuh_timestamp_without_colon_is_normalized_and_auto_blocked(self):
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')
        timestamp = datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%dT%H:%M:%S.%f%z')
        alert = {
            'alert_id': 'wazuh-offset-1', 'timestamp': timestamp,
            'rule_id': '31151', 'rule_level': 10,
            'rule_description': 'Multiple web server 400 errors',
            'rule_groups': '[]', 'agent_id': '001', 'agent_name': 'Ubuntu',
            'src_ip': '192.168.18.103', 'dst_ip': None,
            'src_port': None, 'dst_port': 80, 'full_log': '', 'raw_json': '{}',
        }
        engine = ResponseEngine()
        engine._pfsense_service = Mock()
        engine._pfsense_service.block_ip.return_value = {'status': 'success'}

        summary = engine.process_alerts([alert])

        saved = Alert.query.filter_by(alert_id='wazuh-offset-1').first()
        self.assertEqual(summary['blocked'], 1)
        self.assertEqual(saved.action_taken, 'blocked')
        self.assertIn('+', saved.timestamp)

    def test_existing_invalid_timestamp_alert_is_reprocessed(self):
        deferred = Alert(
            alert_id='invalid-ts-1',
            timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+0000'),
            rule_id='31151', rule_level=10,
            rule_description='Multiple web server 400 errors',
            rule_groups='[]', agent_id='001', agent_name='Ubuntu',
            src_ip='192.168.18.104', raw_json='{}', is_processed=True,
            action_taken='invalid_timestamp',
        )
        db.session.add(deferred)
        db.session.commit()
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')
        engine = ResponseEngine()
        engine._pfsense_service = Mock()
        engine._pfsense_service.block_ip.return_value = {'status': 'success'}

        summary = engine.reprocess_recent_alerts()

        self.assertEqual(summary['blocked'], 1)
        self.assertEqual(db.session.get(Alert, deferred.id).action_taken, 'blocked')

    def test_sql_injection_is_classified_filtered_and_auto_blocked(self):
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')
        alert = {
            'alert_id': 'sqli-alert-1',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'rule_id': '100200', 'rule_level': 12,
            'rule_description': 'Possible SQL injection in web login',
            'rule_groups': '["local", "web_attack", "sql_injection"]',
            'agent_id': '001', 'agent_name': 'Ubuntu',
            'src_ip': '192.168.18.120', 'dst_ip': '10.10.10.30',
            'src_port': 51000, 'dst_port': 80,
            'full_log': 'SQLI ATTEMPT USER=test IP=192.168.18.120',
            'raw_json': '{}',
        }
        engine = ResponseEngine()
        engine._pfsense_service = Mock()
        engine._pfsense_service.block_ip.return_value = {'status': 'success'}

        summary = engine.process_alerts([alert])

        self.assertEqual(summary['blocked'], 1)
        block_call = engine._pfsense_service.block_ip.call_args.args
        self.assertEqual(block_call[0], '192.168.18.120')
        self.assertIn('SQL Injection', block_call[1])
        self.assertIn('Rule 100200', block_call[1])

        response = self.client.get('/api/alerts?threat_type=sql_injection')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['total'], 1)
        self.assertEqual(response.json['items'][0]['threat_type'], 'sql_injection')
        self.assertEqual(response.json['items'][0]['threat_label'], 'SQL Injection')

        response = self.client.get('/api/alerts?threat_type=brute_force')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['total'], 0)

    def test_repeated_sql_injection_reinforces_existing_pfsense_block(self):
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')
        existing = BlockedIP(
            ip_address='192.168.18.121',
            reason='Earlier SQL Injection alert',
            source='auto',
            status='blocked',
            blocked_by='auto-response',
        )
        db.session.add(existing)
        db.session.commit()
        engine = ResponseEngine()
        engine._pfsense_service = Mock()
        engine._pfsense_service.block_ip.return_value = {'status': 'success'}
        alert = {
            'alert_id': 'sqli-repeat-1',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'rule_id': '100200', 'rule_level': 12,
            'rule_description': 'Possible SQL injection in web login',
            'rule_groups': '["sql_injection"]',
            'agent_id': '001', 'agent_name': 'Ubuntu',
            'src_ip': '192.168.18.121', 'dst_ip': '10.10.10.30',
            'src_port': 51001, 'dst_port': 80,
            'full_log': 'SQLI ATTEMPT', 'raw_json': '{}',
        }

        summary = engine.process_alerts([alert])

        self.assertEqual(summary['blocked'], 1)
        self.assertEqual(
            Alert.query.filter_by(alert_id='sqli-repeat-1').first().action_taken,
            'block_reinforced',
        )
        self.assertEqual(
            BlockedIP.query.filter_by(ip_address='192.168.18.121', status='blocked').count(),
            1,
        )
        engine._pfsense_service.block_ip.assert_called_once()

    def test_specific_sql_alert_wins_over_generic_4xx_for_same_request(self):
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')
        now = datetime.now(timezone.utc).isoformat()
        generic = {
            'alert_id': 'same-request-generic', 'timestamp': now,
            'rule_id': '31151', 'rule_level': 10,
            'rule_description': 'Multiple web server 400 error codes from same source ip.',
            'rule_groups': '["web_attack"]', 'agent_id': '001',
            'agent_name': 'Ubuntu', 'src_ip': '192.168.18.122',
            'dst_ip': '10.10.10.30', 'src_port': 51002, 'dst_port': 80,
            'full_log': '', 'raw_json': '{}',
        }
        sql = {
            **generic,
            'alert_id': 'same-request-sql', 'rule_id': '100200',
            'rule_level': 12,
            'rule_description': 'Possible SQL injection in web login',
            'rule_groups': '["web_attack", "sql_injection"]',
        }
        engine = ResponseEngine()
        engine._pfsense_service = Mock()
        engine._pfsense_service.block_ip.return_value = {'status': 'success'}

        # Deliberately supply the generic alert first, matching the observed
        # Wazuh batch order.
        summary = engine.process_alerts([generic, sql])

        block = BlockedIP.query.filter_by(ip_address='192.168.18.122').one()
        self.assertEqual(summary['blocked'], 2)
        self.assertIn('SQL Injection', block.reason)
        self.assertEqual(block.alert.alert_id, 'same-request-sql')
        self.assertEqual(
            Alert.query.filter_by(alert_id='same-request-generic').one().action_taken,
            'block_reinforced',
        )

    def test_later_sql_alert_upgrades_existing_generic_block_reason(self):
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')
        old_alert = Alert(
            alert_id='old-generic', timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=31151, rule_level=10, rule_description='Multiple web errors',
            rule_groups='["web_attack"]', agent_id='001', agent_name='Ubuntu',
            src_ip='192.168.18.123', raw_json='{}', is_processed=True,
            action_taken='blocked',
        )
        db.session.add(old_alert)
        db.session.flush()
        old_block = BlockedIP(
            ip_address='192.168.18.123', reason='Auto-blocked Web Attack',
            source='auto', alert_id=old_alert.id, status='blocked',
            blocked_by='auto-response',
        )
        db.session.add(old_block)
        db.session.commit()
        sql = {
            'alert_id': 'later-sql',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'rule_id': '100200', 'rule_level': 12,
            'rule_description': 'Possible SQL injection in web login',
            'rule_groups': '["sql_injection"]', 'agent_id': '001',
            'agent_name': 'Ubuntu', 'src_ip': '192.168.18.123',
            'dst_ip': '10.10.10.30', 'src_port': 51003, 'dst_port': 80,
            'full_log': 'SQLI ATTEMPT', 'raw_json': '{}',
        }
        engine = ResponseEngine()
        engine._pfsense_service = Mock()
        engine._pfsense_service.block_ip.return_value = {'status': 'success'}

        engine.process_alerts([sql])

        db.session.refresh(old_block)
        self.assertIn('SQL Injection', old_block.reason)
        self.assertEqual(old_block.alert.alert_id, 'later-sql')

    def test_api_datetimes_are_explicit_utc(self):
        record = BlockedIP(
            ip_address='198.51.100.40', reason='Timezone test', status='blocked',
            blocked_at=datetime(2026, 9, 29, 21, 21, 18),
        )
        db.session.add(record)
        db.session.commit()

        payload = record.to_dict()
        self.assertEqual(payload['blocked_at'], '2026-09-29T21:21:18Z')

    def test_web_defacement_alert_is_filtered_without_guessing_an_ip(self):
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')
        alert = {
            'alert_id': 'defacement-1',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'rule_id': '100300', 'rule_level': 12,
            'rule_description': 'Website content injection detected: gambling spam',
            'rule_groups': '["web_defacement", "malicious_content"]',
            'agent_id': '001', 'agent_name': 'STIS', 'src_ip': None,
            'dst_ip': None, 'src_port': None, 'dst_port': None,
            'full_log': '{"event_type":"web_content_threat"}',
            'raw_json': '{}',
        }
        engine = ResponseEngine()
        engine._pfsense_service = Mock()

        summary = engine.process_alerts([alert])

        saved = Alert.query.filter_by(alert_id='defacement-1').one()
        self.assertEqual(summary['actions']['integrity_alert'], 1)
        self.assertEqual(saved.action_taken, 'integrity_alert')
        self.assertEqual(saved.to_dict()['threat_type'], 'web_defacement')
        engine._pfsense_service.block_ip.assert_not_called()
        response = self.client.get('/api/alerts?threat_type=web_defacement')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['total'], 1)
        self.assertEqual(response.json['items'][0]['threat_label'], 'Web Defacement')

    def test_auto_response_status_and_setting_validation(self):
        response = self.client.get('/api/settings/auto-response-status')
        self.assertEqual(response.status_code, 200)
        self.assertIn('scheduler_running', response.json)
        self.assertIn('recent_actions', response.json)
        response = self.client.put('/api/settings', json={'alert_threshold_level': 20})
        self.assertEqual(response.status_code, 400)
        self.assertIn('between 1 and 15', response.json['message'])


if __name__ == '__main__':
    unittest.main()
