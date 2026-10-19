"""Layani filter/detail/pengambilan alert dan alur hapus dengan verifikasi admin."""

from flask import request
from flask_restx import Namespace, Resource
from flask_login import login_required, current_user
from requests import RequestException
from sqlalchemy import String, cast, or_
from app.models import Alert
from app.services.wazuh_service import WazuhService
from app.services.response_engine import ResponseEngine
from app.services import alert_purge_service as purge_service
from app.utils.helpers import create_audit_log
from app.utils.threats import THREAT_RULE_IDS

alerts_ns = Namespace('alerts', description='Security Alerts')


def _admin_only():
    """Batasi operasi retensi ke akun dengan peran admin."""
    return current_user.role == 'admin'


@alerts_ns.route('/purge/preview')
class AlertPurgePreview(Resource):
    method_decorators = [login_required]

    def post(self):
        if not _admin_only():
            return {'message': 'Hanya administrator yang dapat menghapus alert'}, 403
        try:
            period = (request.get_json(silent=True) or {}).get('period')
            return purge_service.preview(current_user, period), 200
        except ValueError as error:
            return {'message': str(error)}, 400
        except RuntimeError as error:
            return {'message': str(error)}, 409
        except (RequestException, KeyError) as error:
            return {'message': f'Pratinjau Indexer gagal: {error}'}, 502


@alerts_ns.route('/purge/confirm')
class AlertPurgeConfirm(Resource):
    method_decorators = [login_required]

    def post(self):
        if not _admin_only():
            return {'message': 'Hanya administrator yang dapat menghapus alert'}, 403
        data = request.get_json(silent=True) or {}
        try:
            return purge_service.confirm(
                current_user, data.get('token'), data.get('password', ''),
                data.get('phrase', ''),
            ), 202
        except PermissionError as error:
            return {'message': str(error)}, 403
        except ValueError as error:
            return {'message': str(error)}, 409
        except RuntimeError as error:
            return {'message': str(error)}, 409
        except (RequestException, KeyError) as error:
            return {'message': f'Indexer gagal: {error}'}, 502


@alerts_ns.route('/purge/<int:purge_id>')
class AlertPurgeStatus(Resource):
    method_decorators = [login_required]

    def get(self, purge_id):
        if not _admin_only():
            return {'message': 'Hanya administrator yang dapat melihat status penghapusan'}, 403
        purge = purge_service.AlertPurge.query.get_or_404(purge_id)
        if purge.status == 'running':
            return purge_service.reconcile(purge), 200
        return purge_service.describe(purge), 200


@alerts_ns.route('/purge/active')
class AlertPurgeActive(Resource):
    method_decorators = [login_required]

    def get(self):
        if not _admin_only():
            return {'message': 'Hanya administrator yang dapat melihat status penghapusan'}, 403
        purge = purge_service.active_purge()
        return {'purge': purge_service.describe(purge) if purge else None}, 200

@alerts_ns.route('')
class AlertList(Resource):
    method_decorators = [login_required]

    def get(self):
        """Get paginated and filtered list of alerts"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        min_level = request.args.get('min_level', type=int)
        max_level = request.args.get('max_level', type=int)
        src_ip = request.args.get('src_ip')
        search = request.args.get('search')
        threat_type = request.args.get('threat_type')
        sort_by = request.args.get('sort_by', 'fetched_at')
        sort_order = request.args.get('sort_order', 'desc')

        query = Alert.query

        if min_level is not None:
            query = query.filter(Alert.rule_level >= min_level)
        if max_level is not None:
            query = query.filter(Alert.rule_level <= max_level)
        if src_ip:
            query = query.filter(Alert.src_ip == src_ip)
        if search:
            query = query.filter(or_(
                Alert.rule_description.ilike(f'%{search}%'),
                cast(Alert.rule_id, String).ilike(f'%{search}%')
            ))
        if threat_type == 'sql_injection':
            query = query.filter(or_(
                Alert.rule_id.in_([int(item) for item in THREAT_RULE_IDS['sql_injection']]),
                Alert.rule_groups.ilike('%sql_injection%'),
                Alert.rule_description.ilike('%sql injection%'),
                Alert.rule_description.ilike('%sqli%'),
            ))
        elif threat_type == 'brute_force':
            query = query.filter(or_(
                Alert.rule_id.in_([int(item) for item in THREAT_RULE_IDS['brute_force']]),
                Alert.rule_groups.ilike('%brute_force%'),
                Alert.rule_groups.ilike('%authentication_failures%'),
                Alert.rule_description.ilike('%brute force%'),
                Alert.rule_description.ilike('%multiple failed login%'),
            ))
        elif threat_type == 'web_defacement':
            query = query.filter(or_(
                Alert.rule_id.in_([int(item) for item in THREAT_RULE_IDS['web_defacement']]),
                Alert.rule_groups.ilike('%web_defacement%'),
                Alert.rule_groups.ilike('%malicious_content%'),
                Alert.rule_description.ilike('%website integrity%'),
                Alert.rule_description.ilike('%content injection%'),
                Alert.rule_description.ilike('%gambling spam%'),
                Alert.rule_description.ilike('%loan spam%'),
            )).filter(Alert.rule_id != 100305)
        elif threat_type == 'host_vulnerability':
            query = query.filter(Alert.rule_groups.ilike('%vulnerability-detector%'))
        elif threat_type == 'rootkit':
            query = query.filter(or_(
                Alert.rule_id.in_([510, 521]),
                Alert.rule_groups.ilike('%rootcheck%'),
            ))
        elif threat_type == 'malware':
            query = query.filter(or_(
                Alert.rule_id == 87105,
                Alert.rule_groups.ilike('%virustotal%'),
            ))
        elif threat_type in THREAT_RULE_IDS:
            query = query.filter(or_(
                Alert.rule_id.in_([int(item) for item in THREAT_RULE_IDS[threat_type]]),
                Alert.rule_groups.ilike(f'%"{threat_type}"%'),
            ))

        if hasattr(Alert, sort_by):
            order_col = getattr(Alert, sort_by)
            if sort_order == 'desc':
                query = query.order_by(order_col.desc())
            else:
                query = query.order_by(order_col.asc())

        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return {
            "items": [item.to_dict() for item in pagination.items],
            "total": pagination.total,
            "page": pagination.page,
            "per_page": pagination.per_page,
            "pages": pagination.pages
        }, 200

@alerts_ns.route('/<int:id>')
class AlertDetail(Resource):
    method_decorators = [login_required]

    def get(self, id):
        """Get alert details by ID"""
        alert = Alert.query.get_or_404(id)
        return alert.to_dict(), 200

@alerts_ns.route('/fetch')
class AlertFetch(Resource):
    method_decorators = [login_required]

    def post(self):
        """Manually trigger alert fetching and processing"""
        if purge_service.active_purge():
            return {'message': 'Tunggu penghapusan alert selesai sebelum mengambil alert baru'}, 409
        try:
            wazuh_service = WazuhService()
            alerts = wazuh_service.get_alerts()

            summary = {"total": 0, "saved": 0, "blocked": 0, "skipped": 0}
            if alerts:
                response_engine = ResponseEngine()
                summary = response_engine.process_alerts(alerts)

            create_audit_log(
                action='fetch_alerts',
                details=f'Manually fetched {len(alerts)} alerts from Wazuh. Summary: {summary}',
                performed_by=current_user.username,
                ip_address=request.remote_addr
            )

            return {
                "message": "Alerts fetched and processed successfully",
                "fetched_count": len(alerts),
                "summary": summary
            }, 200
        except Exception as e:
            create_audit_log(
                action='fetch_alerts',
                details=f'Manual fetch failed: {str(e)}',
                performed_by=current_user.username,
                result='failure',
                error_message=str(e)
            )
            return {"message": f"Error fetching alerts: {str(e)}"}, 500
