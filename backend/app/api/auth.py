"""Kelola login, logout, sesi pengguna, dan pencatatan upaya autentikasi."""

from flask import request
from flask_restx import Namespace, Resource
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timezone
from app.extensions import db
from app.models import User
from app.utils.helpers import create_audit_log

auth_ns = Namespace('auth', description='Authentication')


@auth_ns.route('/login')
class Login(Resource):
    def post(self):
        """Log in a user"""
        data = request.get_json()
        if not data or not data.get('username') or not data.get('password'):
            return {"message": "Username and password are required"}, 400

        user = User.query.filter_by(username=data['username']).first()
        if user and user.check_password(data['password']):
            login_user(user)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            create_audit_log(
                action='login',
                details=f'User {user.username} logged in successfully',
                performed_by=user.username,
                ip_address=request.remote_addr
            )
            return {"message": "Login successful", "user": user.to_dict()}, 200

        create_audit_log(
            action='login',
            details=f"Failed login attempt for username: {data.get('username', 'Unknown')}",
            performed_by=data.get('username', 'unknown'),
            ip_address=request.remote_addr,
            result='failure'
        )
        return {"message": "Invalid credentials"}, 401


@auth_ns.route('/logout')
class Logout(Resource):
    method_decorators = [login_required]

    def post(self):
        """Log out current user"""
        create_audit_log(
            action='logout',
            details=f'User {current_user.username} logged out',
            performed_by=current_user.username,
            ip_address=request.remote_addr
        )
        logout_user()
        return {"message": "Logged out successfully"}, 200


@auth_ns.route('/me')
class CurrentUser(Resource):
    method_decorators = [login_required]

    def get(self):
        """Get current user details"""
        return current_user.to_dict(), 200
