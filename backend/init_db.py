"""Buat tabel dan akun awal hanya jika belum ada; pertahankan database dan password lama."""

import os
from app import create_app
from app.extensions import db
from app.models.user import User
from app.utils.helpers import init_default_settings

def init_database():
    """Create missing tables and defaults without starting alert polling."""
    app = create_app(os.environ.get('FLASK_CONFIG', 'development'), start_scheduler=False)

    with app.app_context():
        # Create all tables based on imported models
        db.create_all()
        print("Database tables created successfully.")

        # Check for default admin user, create if missing
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin = User(username='admin', full_name='Administrator', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created (admin / admin123).")
        else:
            print("Admin user already exists.")

        # Initialize default settings
        init_default_settings()
        print("Default settings initialized successfully.")

        print("Database initialization complete.")

if __name__ == '__main__':
    init_database()
