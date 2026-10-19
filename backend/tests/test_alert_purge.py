"""Safety checks for confirmed, time-bounded Wazuh alert deletion."""

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from app import create_app
from app.extensions import db
from app.models import Alert, BlockedIP, User
from app.services import alert_purge_service as purge


class AlertPurgeTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_scheduler=False)
        self.context = self.app.app_context()
        self.context.push()
        self.user = User(username='purge-admin', role='admin')
        self.user.set_password('test-password')
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def test_retention_cutoffs_are_older_than_selected_age(self):
        now = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(purge.window('week', now=now), (None, '2026-09-28T12:00:00.000Z'))
        self.assertEqual(purge.window('month', now=now), (None, '2026-09-05T12:00:00.000Z'))
        self.assertEqual(purge.window('all', now=now), (None, '2026-10-05T12:00:00.000Z'))

    def test_double_confirmation_preserves_new_alert_and_block_history(self):
        old = Alert(alert_id='old', timestamp='2026-09-01T00:00:00Z', rule_id=1001, rule_level=10)
        new = Alert(alert_id='new', timestamp='2026-10-04T00:00:00Z', rule_id=1002, rule_level=10)
        db.session.add_all([old, new])
        db.session.flush()
        block = BlockedIP(ip_address='192.0.2.20', source='auto', alert_id=old.id)
        db.session.add(block)
        db.session.commit()

        def indexer(method, path, **kwargs):
            if path.endswith('/_count?ignore_unavailable=true&allow_no_indices=true'):
                bounds = kwargs['body']['query']['range']['timestamp']
                self.assertNotIn('gte', bounds)
                self.assertEqual(bounds['lt'], '2026-09-28T12:00:00.000Z')
                return {'count': 1}
            if '_delete_by_query' in path:
                return {'task': 'node:1'}
            if path == '/_tasks/node:1':
                return {'completed': True, 'response': {'deleted': 1, 'failures': []}}
            raise AssertionError(path)

        with patch.object(purge, 'window', return_value=(None, '2026-09-28T12:00:00.000Z')), patch.object(purge, '_indexer', side_effect=indexer):
            preview = purge.preview(self.user, 'week')
            self.assertEqual(preview['soc_count'], 1)
            with self.assertRaises(PermissionError):
                purge.confirm(self.user, preview['token'], 'wrong', purge.PHRASE)
            self.assertEqual(Alert.query.count(), 2)
            job = purge.confirm(self.user, preview['token'], 'test-password', purge.PHRASE)
            self.assertEqual(Alert.query.count(), 2)  # Wait for the Indexer task.
            result = purge.reconcile(purge.AlertPurge.query.get(job['id']))

        self.assertEqual(result['status'], 'complete')
        self.assertEqual([alert.alert_id for alert in Alert.query.all()], ['new'])
        self.assertIsNone(db.session.get(BlockedIP, block.id).alert_id)


if __name__ == '__main__':
    unittest.main()
