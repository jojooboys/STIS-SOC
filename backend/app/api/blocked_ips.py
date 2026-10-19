"""Kelola block/unblock/reblock, sinkronisasi alias, dan riwayat IP yang sudah dilepas."""

from flask import request
from flask_restx import Namespace, Resource
from flask_login import login_required, current_user
from sqlalchemy import or_
from datetime import datetime, timezone
from app.extensions import db
from app.models import BlockedIP
from app.services.response_engine import ResponseEngine
from app.services.pfsense_service import PfSenseService
from app.utils.helpers import create_audit_log, get_setting, DEFAULT_WHITELIST
from app.utils.validators import is_valid_ipv4, is_ip_in_whitelist

blocked_ips_ns = Namespace('blocked-ips', description='Blocked IP Management')

@blocked_ips_ns.route('')
class BlockedIPList(Resource):
    method_decorators = [login_required]

    def get(self):
        """Get paginated list of blocked IPs"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status = request.args.get('status', 'all')
        search = request.args.get('search')

        query = BlockedIP.query

        if status != 'all':
            query = query.filter_by(status=status)

        if search:
            query = query.filter(or_(
                BlockedIP.ip_address.ilike(f'%{search}%'),
                BlockedIP.reason.ilike(f'%{search}%')
            ))

        query = query.order_by(BlockedIP.blocked_at.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return {
            "items": [item.to_dict() for item in pagination.items],
            "total": pagination.total,
            "page": pagination.page,
            "per_page": pagination.per_page,
            "pages": pagination.pages
        }, 200

    def post(self):
        """Manually block an IP address"""
        data = request.get_json()
        if not isinstance(data, dict):
            return {"message": "IP address and reason are required"}, 400

        ip_address = str(data.get('ip_address') or '').strip()
        reason = str(data.get('reason') or '').strip()
        if not ip_address or not reason:
            return {"message": "IP address and reason are required"}, 400

        if not is_valid_ipv4(ip_address):
            return {"message": "Invalid IPv4 address format"}, 400
        if is_ip_in_whitelist(ip_address, get_setting('whitelist_ips', DEFAULT_WHITELIST)):
            return {"message": f"IP {ip_address} is protected by the SOC whitelist"}, 400

        existing = BlockedIP.query.filter_by(ip_address=ip_address, status='blocked').first()
        if existing:
            return {"message": f"IP {ip_address} is already blocked"}, 400

        try:
            engine = ResponseEngine()
            result = engine.manual_block(ip_address, reason, current_user.username)
            if result.get('status') == 'success':
                return {"message": result.get('message')}, 201
            return {"message": result.get('message', 'Failed to block IP')}, 400
        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500

@blocked_ips_ns.route('/history')
class BlockedIPHistory(Resource):
    method_decorators = [login_required]

    def delete(self):
        """Delete selected unblocked history rows; never change pfSense."""
        data = request.get_json(silent=True) or {}
        ids = data.get('ids')
        if not isinstance(ids, list) or not ids or any(type(item) is not int or item <= 0 for item in ids):
            return {"message": "Select one or more unblocked records to delete"}, 400
        ids = list(dict.fromkeys(ids))
        records = BlockedIP.query.filter(BlockedIP.id.in_(ids)).all()
        if len(records) != len(ids):
            return {"message": "One or more selected records no longer exist"}, 404
        if any(record.status != 'unblocked' for record in records):
            return {"message": "Only unblocked records can be deleted"}, 400

        for record in records:
            db.session.delete(record)
        create_audit_log(
            action='delete_block_history',
            details=f"Deleted {len(records)} unblocked history records (IDs: {', '.join(map(str, ids))})",
            performed_by=current_user.username,
            ip_address=request.remote_addr,
        )
        return {"message": f"Deleted {len(records)} unblocked history records", "deleted": len(records)}, 200

@blocked_ips_ns.route('/<int:id>/reblock')
class BlockedIPReblock(Resource):
    method_decorators = [login_required]

    def post(self, id):
        """Restore a block from an unblocked history row."""
        record = db.session.get(BlockedIP, id)
        if record is None:
            return {"message": "Block record not found"}, 404
        if record.status != 'unblocked':
            return {"message": "Only unblocked records can be blocked again"}, 400
        if is_ip_in_whitelist(record.ip_address, get_setting('whitelist_ips', DEFAULT_WHITELIST)):
            return {"message": f"IP {record.ip_address} is protected by the SOC whitelist"}, 400
        existing = BlockedIP.query.filter_by(ip_address=record.ip_address, status='blocked').first()
        if existing:
            return {"message": f"IP {record.ip_address} is already blocked"}, 400

        result = ResponseEngine().manual_reblock(record, current_user.username)
        return {"message": result.get('message', 'Failed to block IP')}, 200 if result.get('status') == 'success' else 400

@blocked_ips_ns.route('/<int:id>')
class BlockedIPDetail(Resource):
    method_decorators = [login_required]

    def delete(self, id):
        """Manually unblock an IP address"""
        blocked_ip = BlockedIP.query.get_or_404(id)
        if blocked_ip.status != 'blocked':
            return {"message": "IP is not currently blocked"}, 400

        try:
            engine = ResponseEngine()
            result = engine.manual_unblock(id, current_user.username)
            if result.get('status') == 'success':
                return {"message": result.get('message')}, 200
            return {"message": result.get('message', 'Failed to unblock IP')}, 400
        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500

@blocked_ips_ns.route('/sync')
class BlockedIPSync(Resource):
    method_decorators = [login_required]

    def post(self):
        """Reconcile local block status with the pfSense alias."""
        try:
            pfsense = PfSenseService()
            result = pfsense.read_blocklist()
            if result.get('status') != 'success':
                return {"message": result.get('message', 'Cannot read pfSense blocklist')}, 502

            current_blocks = set(result['addresses'])
            active_records = BlockedIP.query.filter_by(status='blocked').all()
            recorded = {record.ip_address for record in active_records if record.ip_address in current_blocks}
            removed = 0
            added = 0
            for record in active_records:
                if record.ip_address not in current_blocks:
                    record.status = 'unblocked'
                    record.unblocked_at = datetime.now(timezone.utc)
                    record.unblocked_by = 'pfSense sync'
                    removed += 1
            for ip_address in sorted(current_blocks - recorded):
                db.session.add(BlockedIP(
                    ip_address=ip_address,
                    reason='Imported from pfSense alias',
                    source='sync',
                    status='blocked',
                    blocked_by='pfSense sync',
                ))
                added += 1
            create_audit_log(
                action='sync_blocklist',
                details=f"pfSense alias {pfsense.alias_name}: {len(current_blocks)} addresses, {added} imported, {removed} local records marked unblocked",
                performed_by=current_user.username,
                ip_address=request.remote_addr,
            )
            return {"message": "Sync complete", "pfsense_count": len(current_blocks), "imported": added, "marked_unblocked": removed}, 200
        except Exception as e:
            db.session.rollback()
            return {"message": f"Sync failed: {str(e)}"}, 500
