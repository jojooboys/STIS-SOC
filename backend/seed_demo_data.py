"""Isi database demo dari CSV sintetis; tidak menjalankan scheduler/firewall.

Jalankan dari backend: python seed_demo_data.py [--reset]. Database soc.db dan
DATABASE_URL pada .env tidak dipakai. Reset hanya berlaku pada instance/demo.db.
"""

import argparse
from datetime import datetime, timezone
from pathlib import Path

from app import create_app
from app.extensions import db
from app.models import Alert, AuditLog, BlockedIP, User
from app.utils.helpers import init_default_settings
from demo_dataset import load_cases

DEMO_DB = Path(__file__).resolve().parent / 'instance' / 'demo.db'


def create_demo_app():
    """Tetapkan lokasi demo sebelum SQLAlchemy membuka koneksi database."""
    DEMO_DB.parent.mkdir(parents=True, exist_ok=True)
    return create_app('development', start_scheduler=False, config_overrides={
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{DEMO_DB.as_posix()}',
        'DEBUG': False,
    })


def seed_demo_data(*, reset=False):
    """Isi contoh UI; hentikan pengisian ulang kecuali --reset diberikan."""
    cases = load_cases()
    app = create_demo_app()
    try:
        with app.app_context():
            populated = Alert.query.count() or BlockedIP.query.count() or AuditLog.query.count()
            if populated and not reset:
                raise ValueError('Database demo sudah terisi. Gunakan --reset untuk mengganti data demo.')
            if reset:
                # Urutan ini menjaga referensi BlockedIP -> Alert saat foreign key aktif.
                BlockedIP.query.delete()
                Alert.query.delete()
                AuditLog.query.delete()
            if not User.query.filter_by(username='admin').first():
                admin = User(username='admin', full_name='Administrator Demo', role='admin')
                admin.set_password('admin123')
                db.session.add(admin)
            for case in cases:
                fields = dict(case['alert'])
                decision = case['expected_action']
                alert = Alert(**fields, is_processed=True,
                              action_taken='blocked' if decision == 'block' else decision)
                db.session.add(alert)
                db.session.flush()
                if decision == 'block':
                    # Riwayat ilustrasi UI saja; tidak ada panggilan API pfSense.
                    db.session.add(BlockedIP(
                        ip_address=alert.src_ip, alert_id=alert.id, source='auto',
                        status='blocked', reason='SIMULASI: contoh keputusan dataset dummy',
                        blocked_by='demo-simulator', blocked_at=datetime.now(timezone.utc),
                    ))
            db.session.add(AuditLog(
                action='demo_seed', details='SIMULASI: dataset sintetis dimuat tanpa koneksi firewall',
                performed_by='demo-simulator', result='success',
            ))
            db.session.commit()
            init_default_settings()
    finally:
        # Tutup koneksi SQLite juga ketika pengisian ulang ditolak.
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
    print(f'{len(cases)} alert sintetis dimuat ke {DEMO_DB}.')
    print('Jalankan python run.py --demo; login demo admin / admin123.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reset', action='store_true', help='Ganti hanya data pada database demo')
    try:
        seed_demo_data(reset=parser.parse_args().reset)
    except ValueError as error:
        parser.exit(2, f'{error}\n')
