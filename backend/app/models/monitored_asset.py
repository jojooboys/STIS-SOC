"""Legacy website/service metadata retained for old records.

New targets use Agent-side log/FIM conventions; this table is read only when
attributing alerts that predate the inventory change.
"""

from datetime import datetime, timezone

from app.extensions import db
from app.utils.dates import isoformat_utc


class MonitoredAsset(db.Model):
    __tablename__ = 'monitored_assets'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    kind = db.Column(db.String(20), nullable=False, default='website')
    domain = db.Column(db.String(255), nullable=True)
    path_prefix = db.Column(db.String(255), nullable=False, default='/')
    agent_id = db.Column(db.String(20), nullable=False, index=True)
    agent_name = db.Column(db.String(120), nullable=False)
    access_log_path = db.Column(db.String(500), nullable=True)
    app_log_path = db.Column(db.String(500), nullable=True)
    app_log_format = db.Column(db.String(20), nullable=False, default='syslog')
    root_path = db.Column(db.String(500), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    sync_status = db.Column(db.String(20), nullable=False, default='pending')
    sync_error = db.Column(db.Text, nullable=True)
    last_synced_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'kind': self.kind,
            'domain': self.domain,
            'path_prefix': self.path_prefix,
            'agent_id': self.agent_id,
            'agent_name': self.agent_name,
            'access_log_path': self.access_log_path,
            'app_log_path': self.app_log_path,
            'app_log_format': self.app_log_format,
            'root_path': self.root_path,
            'enabled': self.enabled,
            'sync_status': self.sync_status,
            'sync_error': self.sync_error,
            'last_synced_at': isoformat_utc(self.last_synced_at),
            'created_at': isoformat_utc(self.created_at),
        }
