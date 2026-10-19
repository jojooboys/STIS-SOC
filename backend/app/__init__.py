"""Bangun aplikasi Flask, inisialisasi database, registrasikan API, lalu opsional mulai scheduler."""

import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

from app.config import config
from app.extensions import db, login_manager, bcrypt

logger = logging.getLogger(__name__)


def create_app(config_name: str = None, *, start_scheduler: bool = True,
               config_overrides: dict = None) -> Flask:
    """
    Factory function to create and configure the Flask application.

    Args:
        config_name (str): Configuration mapping name (e.g., 'development', 'production').
        start_scheduler (bool): Disable background processing for diagnostics and tests.
        config_overrides (dict): Explicit overrides applied before database initialization.

    Returns:
        Flask: The configured Flask application instance.
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'development')

    app = Flask(__name__)
    app.config.from_object(config.get(config_name, config['default']))
    if config_overrides:
        # Demo/evaluation must select their isolated database before db.init_app.
        app.config.update(config_overrides)

    # Initialize Extensions
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)

    # Setup CORS to allow local and VirtualBox Host-Only network access
    import re
    cors_origins = [
        re.compile(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"),
        re.compile(r"^https?://(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?$")
    ]
    CORS(app, origins=cors_origins, supports_credentials=True)

    # Configure Login Manager
    login_manager.session_protection = 'strong'

    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({"message": "Authentication required"}), 401

    # Register API Blueprint
    from app.api import api_bp
    app.register_blueprint(api_bp)

    # Create database tables and initialize scheduler
    with app.app_context():
        # Import all models so SQLAlchemy registers them
        from app.models import User, Alert, BlockedIP, AuditLog, SocSetting, MonitoredAsset, MonitoredServer  # noqa: F401
        db.create_all()

        # Initialize background scheduler for alert polling
        try:
            from app.services.scheduler_service import init_scheduler
            if start_scheduler:
                init_scheduler(app)
        except Exception as e:
            logger.warning(f"Scheduler initialization skipped: {e}")

    return app
