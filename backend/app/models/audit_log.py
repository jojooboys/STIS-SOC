"""Simpan siapa melakukan tindakan, kapan, hasil, dan pesan kesalahannya."""

from datetime import datetime, timezone
from app.extensions import db
from app.utils.dates import isoformat_utc

class AuditLog(db.Model):
    """AuditLog model recording important actions and system events."""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    performed_by = db.Column(db.String(80), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    result = db.Column(db.String(20), nullable=True, default='success') # 'success' or 'failure'
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self) -> dict:
        """Convert the AuditLog object to a dictionary."""
        return {
            'id': self.id,
            'action': self.action,
            'details': self.details,
            'performed_by': self.performed_by,
            'ip_address': self.ip_address,
            'result': self.result,
            'error_message': self.error_message,
            'created_at': isoformat_utc(self.created_at)
        }
