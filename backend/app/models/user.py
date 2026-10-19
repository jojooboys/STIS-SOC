"""Simpan akun SOC, hash password bcrypt, dan data sesi Flask-Login."""

from datetime import datetime, timezone
from flask_login import UserMixin
from app.extensions import db, bcrypt
from app.utils.dates import isoformat_utc

class User(db.Model, UserMixin):
    """User model for authentication and role-based access control."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    role = db.Column(db.String(20), default='admin', nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password: str) -> None:
        """Hash the provided password and store it."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password: str) -> bool:
        """Verify the provided password against the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self) -> dict:
        """Convert the User object to a dictionary, excluding sensitive fields."""
        return {
            'id': self.id,
            'username': self.username,
            'full_name': self.full_name,
            'role': self.role,
            'created_at': isoformat_utc(self.created_at),
            'last_login': isoformat_utc(self.last_login)
        }
