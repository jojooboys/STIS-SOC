"""Simpan riwayat blokir, relasi alert, pelaksana, dan waktu unblock."""

from datetime import datetime, timezone
from app.extensions import db
from app.utils.dates import isoformat_utc

class BlockedIP(db.Model):
    """BlockedIP model tracking network blocks implemented via pfSense."""
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    reason = db.Column(db.Text, nullable=True)
    source = db.Column(db.String(20), nullable=False, default='auto') # 'auto' or 'manual'
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), nullable=True)
    pfsense_rule_id = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='blocked', index=True)
    blocked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    unblocked_at = db.Column(db.DateTime, nullable=True)
    blocked_by = db.Column(db.String(80), nullable=True)
    unblocked_by = db.Column(db.String(80), nullable=True)

    def to_dict(self) -> dict:
        """Convert the BlockedIP object to a dictionary."""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'source': self.source,
            'alert_id': self.alert_id,
            'pfsense_rule_id': self.pfsense_rule_id,
            'status': self.status,
            'blocked_at': isoformat_utc(self.blocked_at),
            'unblocked_at': isoformat_utc(self.unblocked_at),
            'blocked_by': self.blocked_by,
            'unblocked_by': self.unblocked_by
        }
