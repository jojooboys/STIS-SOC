"""Uji pembacaan alert dan diagnosis Wazuh menggunakan respons jaringan tiruan."""

import unittest
from unittest.mock import Mock, patch
import requests

from app import create_app
from app.extensions import db
from app.models import User
from app.services.wazuh_service import WazuhService


class WazuhTests(unittest.TestCase):
    def setUp(self):
        self.service = WazuhService()
        self.service._get_config = Mock(return_value={
            'wazuh_host': 'localhost', 'wazuh_api_port': '55000',
            'wazuh_indexer_port': '9200', 'wazuh_api_user': 'test',
            'wazuh_api_password': 'test', 'wazuh_indexer_user': 'test',
            'wazuh_indexer_password': 'test',
        })
        self.service.session = Mock()

    def test_indexer_failure_is_not_an_empty_success(self):
        self.service.session.post.side_effect = requests.ConnectionError('Indexer unavailable')
        with self.assertRaises(requests.ConnectionError):
            self.service.get_alerts()

    def test_empty_index_is_valid(self):
        self.service.session.post.return_value.json.return_value = {'hits': {'hits': []}}
        self.assertEqual(self.service.get_alerts(), [])

    def test_incremental_fetch_reads_oldest_unprocessed_alerts_first(self):
        self.service.session.post.return_value.json.return_value = {'hits': {'hits': []}}
        self.service.get_alerts(since='2026-09-29T10:00:00Z')
        query = self.service.session.post.call_args.kwargs['json']
        self.assertEqual(query['sort'][0]['timestamp']['order'], 'asc')

    def test_manager_failure_does_not_skip_indexer_test(self):
        self.service.session.post.side_effect = requests.Timeout('Manager timeout')
        result = self.service.test_connection()
        self.assertEqual(result['status'], 'failure')
        self.assertFalse(result['manager'])
        self.assertTrue(result['indexer'])

    def test_both_connections_success(self):
        self.assertEqual(self.service.test_connection()['status'], 'success')

    def test_login_dashboard_and_failed_fetch_api(self):
        app = create_app('testing', start_scheduler=False)
        with app.app_context():
            user = User(username='test')
            user.set_password('test-only')
            db.session.add(user)
            db.session.commit()
        client = app.test_client()
        self.assertEqual(client.post('/api/auth/login', json={'username': 'test', 'password': 'test-only'}).status_code, 200)
        result = client.get('/api/dashboard/stats')
        self.assertEqual(result.status_code, 200)
        for key in ['total_alerts', 'alerts_today', 'active_blocks', 'critical_alerts']:
            self.assertEqual(result.json[key], 0)
        self.assertEqual(client.get('/api/alerts?per_page=10').json['items'], [])
        with patch.object(WazuhService, 'get_alerts', side_effect=requests.ConnectionError('Indexer unavailable')):
            result = client.post('/api/alerts/fetch')
        self.assertEqual(result.status_code, 500)
        self.assertIn('Indexer unavailable', result.json['message'])


if __name__ == '__main__':
    unittest.main()
