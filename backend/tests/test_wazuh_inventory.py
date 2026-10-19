"""The dashboard can inspect Wazuh, but cannot enroll or change assets."""

import json
import unittest
from unittest.mock import patch

import requests

from app import create_app
from app.extensions import db
from app.models import Alert, MonitoredAsset, MonitoredServer, User
from app.services.wazuh_service import WazuhService


class WazuhInventoryTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_scheduler=False)
        self.context = self.app.app_context()
        self.context.push()
        user = User(username='inventory-admin', role='admin')
        user.set_password('test-only')
        db.session.add(user)
        db.session.commit()
        self.client = self.app.test_client()
        self.client.post('/api/auth/login', json={'username': 'inventory-admin', 'password': 'test-only'})

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def test_agents_are_read_directly_from_wazuh(self):
        with patch.object(WazuhService, 'get_agents', return_value=[
            {'id': '000', 'name': 'manager'},
            {'id': '001', 'name': 'STIS', 'status': 'active', 'ip': '10.10.10.30'},
        ]):
            response = self.client.get('/api/assets/agents')
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item['id'] for item in response.json['items']], ['001'])

    def test_inventory_survives_one_unavailable_section(self):
        with patch.object(WazuhService, 'get_agents', return_value=[
            {'id': '001', 'name': 'STIS', 'status': 'active'},
        ]), patch.object(WazuhService, '_manager_request', side_effect=[
            {'data': {'affected_items': [{'name': 'apache2'}], 'total_affected_items': 1}},
            requests.HTTPError('service inventory unavailable'),
            {'data': {'affected_items': []}},
            {'data': {'localfile': [{'location': '/var/log/stis-soc/apache/*.log'}]}},
            {'data': {'syscheck': {'directories': [{'path': '/var/www'}]}}},
        ]):
            response = self.client.get('/api/assets/agents/001/inventory')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['sections']['packages']['items'][0]['name'], 'apache2')
        self.assertIn('services', response.json['errors'])
        self.assertEqual(response.json['sections']['log_sources']['items'][0]['location'],
                         '/var/log/stis-soc/apache/*.log')

    def test_removed_crud_routes_cannot_change_legacy_tables(self):
        db.session.add(MonitoredServer(agent_id='001', agent_name='STIS', display_name='STIS'))
        db.session.add(MonitoredAsset(name='web1', kind='website', agent_id='001',
                                      agent_name='STIS', access_log_path='/var/log/apache2/web1.log'))
        db.session.commit()
        for method, path in [
            ('post', '/api/assets'), ('post', '/api/assets/servers'),
            ('put', '/api/assets/servers/1'), ('delete', '/api/assets/servers/1'),
            ('put', '/api/assets/1'), ('delete', '/api/assets/1'),
            ('post', '/api/assets/sync'),
        ]:
            response = getattr(self.client, method)(path, json={})
            self.assertIn(response.status_code, (404, 405), (method, path))
        self.assertEqual(MonitoredServer.query.count(), 1)
        self.assertEqual(MonitoredAsset.query.count(), 1)

    def test_alert_identifies_site_without_soc_asset_row(self):
        alert = Alert(
            alert_id='global-site', timestamp='2026-10-02T00:00:00Z',
            rule_id=100430, rule_level=12, rule_description='Sensitive file probe',
            rule_groups='["sensitive_file"]', agent_id='001', agent_name='STIS',
            src_ip='192.0.2.10', full_log='192.0.2.10 - - "GET /.env HTTP/1.1" 404 1',
            raw_json=json.dumps({'location': '(STIS) any->/var/log/stis-soc/apache/web1.access.log',
                                 'data': {'url': '/.env'}}),
        )
        db.session.add(alert)
        db.session.commit()
        detail = self.client.get(f'/api/alerts/{alert.id}').json
        self.assertEqual(detail['asset_name'], 'web1')
        self.assertEqual(detail['target'], '/.env')

        # A different legacy site on the same Agent must not supply a wrong
        # domain to an alert identified by the new Agent-side log path.
        db.session.add(MonitoredAsset(name='old-site', kind='website', agent_id='001',
                                      agent_name='STIS', domain='old.example.test',
                                      access_log_path='/var/log/apache2/old_access.log'))
        db.session.commit()
        detail = self.client.get(f'/api/alerts/{alert.id}').json
        self.assertEqual(detail['asset_name'], 'web1')
        self.assertIsNone(detail['domain'])


if __name__ == '__main__':
    unittest.main()
