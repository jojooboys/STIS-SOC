"""Simpan konfigurasi integrasi serta kebijakan respons dalam pasangan key-value."""

from datetime import datetime, timezone
from app.extensions import db
from app.utils.dates import isoformat_utc

class SocSetting(db.Model):
    """Model for storing dynamic configuration settings for the SOC application."""
    __tablename__ = 'soc_settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    updated_by = db.Column(db.String(80), nullable=True)

    def to_dict(self) -> dict:
        """Convert the SocSetting object to a dictionary."""
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value,
            'description': self.description,
            'updated_at': isoformat_utc(self.updated_at),
            'updated_by': self.updated_by
        }
