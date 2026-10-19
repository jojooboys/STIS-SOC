"""Sajikan jejak tindakan dengan filter dan pagination untuk investigasi operator."""

from flask import request
from flask_restx import Namespace, Resource
from flask_login import login_required
from sqlalchemy import or_
from app.models import AuditLog

audit_ns = Namespace('audit', description='Audit Logs')

@audit_ns.route('')
class AuditList(Resource):
    method_decorators = [login_required]

    def get(self):
        """Get paginated list of audit logs"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        action = request.args.get('action')
        search = request.args.get('search')

        query = AuditLog.query

        if action:
            query = query.filter_by(action=action)

        if search:
            query = query.filter(or_(
                AuditLog.details.ilike(f'%{search}%'),
                AuditLog.ip_address.ilike(f'%{search}%'),
                AuditLog.performed_by.ilike(f'%{search}%')
            ))

        query = query.order_by(AuditLog.created_at.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return {
            "items": [item.to_dict() for item in pagination.items],
            "total": pagination.total,
            "page": pagination.page,
            "per_page": pagination.per_page,
            "pages": pagination.pages
        }, 200
