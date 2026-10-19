"""Legacy server records retained for existing SOC databases.

Current server inventory is read from the Wazuh Manager API, not this table.
"""

from datetime import datetime, timezone

from app.extensions import db
from app.utils.dates import isoformat_utc


class MonitoredServer(db.Model):
    __tablename__ = 'monitored_servers'

    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    agent_name = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'agent_name': self.agent_name,
            'display_name': self.display_name,
            'description': self.description,
            'enabled': self.enabled,
            'created_at': isoformat_utc(self.created_at),
        }
