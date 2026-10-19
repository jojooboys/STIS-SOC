"""Simpan alert Wazuh, hasil respons, dan konteks investigasi yang dikirim ke antarmuka."""

from datetime import datetime, timezone
from app.extensions import db
from app.utils.dates import isoformat_utc

class Alert(db.Model):
    """Alert model representing security events fetched from Wazuh."""
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(100), unique=True, nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)
    rule_id = db.Column(db.Integer, nullable=False)
    rule_description = db.Column(db.Text, nullable=True)
    rule_level = db.Column(db.Integer, index=True, nullable=False)
    rule_groups = db.Column(db.Text, nullable=True)
    agent_id = db.Column(db.String(20), nullable=True)
    agent_name = db.Column(db.String(100), nullable=True)
    src_ip = db.Column(db.String(45), index=True, nullable=True)
    dst_ip = db.Column(db.String(45), nullable=True)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    full_log = db.Column(db.Text, nullable=True)
    raw_json = db.Column(db.Text, nullable=True)
    is_processed = db.Column(db.Boolean, default=False)
    action_taken = db.Column(db.String(50), nullable=True)
    fetched_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship to BlockedIP
    blocked_ips = db.relationship('BlockedIP', backref='alert', lazy=True)

    def to_dict(self) -> dict:
        """Convert the Alert object to a dictionary."""
        from app.utils.incident import describe_incident
        from app.utils.threats import classify_alert

        threat = classify_alert(self)
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'timestamp': self.timestamp,
            'rule_id': self.rule_id,
            'rule_description': self.rule_description,
            'rule_level': self.rule_level,
            'rule_groups': self.rule_groups,
            'agent_id': self.agent_id,
            'agent_name': self.agent_name,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'full_log': self.full_log,
            'raw_json': self.raw_json,
            'is_processed': self.is_processed,
            'action_taken': self.action_taken,
            'threat_type': threat['code'],
            'threat_label': threat['label'],
            'fetched_at': isoformat_utc(self.fetched_at),
            **describe_incident(self),
        }
