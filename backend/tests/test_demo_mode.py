"""Pastikan preview sintetis terisolasi dari database operasional dan jaringan."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.extensions import db
from app.models import Alert, BlockedIP
from demo_dataset import load_cases
from seed_demo_data import create_demo_app, seed_demo_data


class DemoModeTests(unittest.TestCase):
    """Gunakan direktori sementara; tes tidak menyentuh instance pengguna."""

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.demo_path = Path(self.temp.name) / 'demo.db'
        self.operational_path = Path(self.temp.name) / 'soc.db'
        self.operational_path.write_bytes(b'operational database must remain unchanged')
        self.enterContext(patch('seed_demo_data.DEMO_DB', self.demo_path))
        self.enterContext(patch.dict('os.environ', {
            'DATABASE_URL': f'sqlite:///{self.operational_path.as_posix()}'
        }))
        self.http = self.enterContext(patch(
            'requests.sessions.Session.request', side_effect=AssertionError('Unexpected HTTP')
        ))
        self.scheduler = self.enterContext(patch('app.services.scheduler_service.init_scheduler'))
        self.enterContext(redirect_stdout(io.StringIO()))

    def test_seed_uses_demo_database_and_never_starts_integrations(self):
        seed_demo_data()
        app = create_demo_app()
        client = app.test_client()
        self.assertEqual(client.post('/api/auth/login', json={
            'username': 'admin', 'password': 'admin123'
        }).status_code, 200)
        self.assertEqual(client.get('/api/alerts').json['total'], 12)
        self.assertEqual(client.get('/api/dashboard/stats').status_code, 200)
        with app.app_context():
            self.assertEqual(Alert.query.count(), 12)
            self.assertEqual(BlockedIP.query.count(), 3)
            db.session.remove()
            db.engine.dispose()
        self.assertEqual(self.operational_path.read_bytes(), b'operational database must remain unchanged')
        self.scheduler.assert_not_called()
        self.http.assert_not_called()

    def test_reseed_requires_explicit_reset_and_preserves_existing_rows(self):
        seed_demo_data()
        with self.assertRaises(ValueError):
            seed_demo_data()
        seed_demo_data(reset=True)
        app = create_demo_app()
        with app.app_context():
            self.assertEqual(Alert.query.count(), 12)
            db.session.remove()
            db.engine.dispose()
        self.http.assert_not_called()

    def test_invalid_dataset_is_rejected_before_database_changes(self):
        with patch('seed_demo_data.load_cases', side_effect=ValueError('Invalid CSV')):
            with self.assertRaises(ValueError):
                seed_demo_data(reset=True)
        self.assertFalse(self.demo_path.exists())

    def test_public_cases_include_minimum_rows_and_missing_source_ip(self):
        cases = load_cases()
        self.assertGreaterEqual(len(cases), 5)
        self.assertTrue(any(c['alert']['src_ip'] is None for c in cases))
        self.assertTrue(all(c['alert']['full_log'].startswith('SYNTHETIC') for c in cases))


if __name__ == '__main__':
    unittest.main()
