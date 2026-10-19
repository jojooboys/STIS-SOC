"""Short-lived, single-use approval and progress record for alert deletion."""

from datetime import datetime, timezone

from app.extensions import db


class AlertPurge(db.Model):
    __tablename__ = 'alert_purges'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    period = db.Column(db.String(20), nullable=False)
    scope = db.Column(db.String(12), nullable=False)
    from_utc = db.Column(db.String(40), nullable=True)
    to_utc = db.Column(db.String(40), nullable=False)
    expected_indexer = db.Column(db.Integer, nullable=False)
    expected_soc = db.Column(db.Integer, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default='pending', index=True)
    task_id = db.Column(db.String(180), nullable=True)
    indexer_deleted = db.Column(db.Integer, nullable=False, default=0)
    soc_deleted = db.Column(db.Integer, nullable=False, default=0)
    error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
