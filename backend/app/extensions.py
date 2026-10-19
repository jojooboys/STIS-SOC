"""Sediakan satu instance ekstensi bersama agar model dan API tidak saling mengimpor aplikasi."""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

# Initialize SQLAlchemy ORM
db = SQLAlchemy()

# Initialize Flask-Login for user session management
login_manager = LoginManager()

# Initialize Flask-Bcrypt for password hashing
bcrypt = Bcrypt()
