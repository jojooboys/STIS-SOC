"""Validasi konfigurasi SOC, samarkan secret pada respons, dan uji koneksi integrasi."""

from flask import request
from flask_restx import Namespace, Resource
from flask_login import login_required, current_user
from app.models import SocSetting
from app.utils.helpers import set_setting, create_audit_log
from app.models import Alert

settings_ns = Namespace('settings', description='SOC Configuration')

# Keys whose values should be masked in GET responses
SENSITIVE_KEYS = [
    'wazuh_api_password', 'wazuh_indexer_password', 'pfsense_api_key'
]


@settings_ns.route('')
class SettingsManager(Resource):
    method_decorators = [login_required]

    def get(self):
        """Get all SOC settings"""
        settings = SocSetting.query.all()
        result = {}
        for s in settings:
            if s.key.startswith('auto_response_last_') or s.key == 'last_fetch_timestamp':
                continue
            if s.key in SENSITIVE_KEYS and s.value:
                result[s.key] = '********'
            else:
                result[s.key] = s.value
        return result, 200

    def put(self):
        """Update multiple SOC settings"""
        data = request.get_json()
        if not data:
            return {"message": "No data provided"}, 400

        updated_keys = []
        numeric_ranges = {
            'alert_threshold_level': (1, 15),
            'polling_interval_seconds': (10, 86400),
            'auto_response_max_alert_age_seconds': (60, 86400),
        }
        for key, value in data.items():
            # Skip masked passwords — don't overwrite with placeholder
            if key in SENSITIVE_KEYS and value == '********':
                continue
            if key in numeric_ranges:
                try:
                    numeric_value = int(value)
                except (TypeError, ValueError):
                    return {"message": f"{key} must be a whole number"}, 400
                minimum, maximum = numeric_ranges[key]
                if numeric_value < minimum or numeric_value > maximum:
                    return {"message": f"{key} must be between {minimum} and {maximum}"}, 400
                value = numeric_value
            set_setting(key, str(value), updated_by=current_user.username)
            updated_keys.append(key)

        if updated_keys:
            create_audit_log(
                action='config_change',
                details=f"Updated settings: {', '.join(updated_keys)}",
                performed_by=current_user.username,
                ip_address=request.remote_addr
            )

        # Apply scheduler changes immediately in the running backend process.
        try:
            from datetime import datetime, timezone
            from app.services.scheduler_service import scheduler, reschedule_polling_job
            if 'polling_interval_seconds' in updated_keys:
                reschedule_polling_job(int(data['polling_interval_seconds']))
            if str(data.get('auto_response_enabled', '')).lower() == 'true':
                job = scheduler.get_job('poll_wazuh_alerts')
                if job:
                    job.modify(next_run_time=datetime.now(timezone.utc))
        except Exception:
            # Settings remain valid even if this process was intentionally started without a scheduler.
            pass

        # Return updated settings
        settings = SocSetting.query.all()
        result = {}
        for s in settings:
            if s.key.startswith('auto_response_last_') or s.key == 'last_fetch_timestamp':
                continue
            if s.key in SENSITIVE_KEYS and s.value:
                result[s.key] = '********'
            else:
                result[s.key] = s.value
        return result, 200


@settings_ns.route('/auto-response-status')
class AutoResponseStatus(Resource):
    method_decorators = [login_required]

    def get(self):
        """Return current auto-response settings, scheduler health, and recent decisions."""
        from app.utils.helpers import get_setting, DEFAULT_WHITELIST
        from app.services.scheduler_service import scheduler

        job = scheduler.get_job('poll_wazuh_alerts') if scheduler.running else None
        recent = Alert.query.order_by(Alert.id.desc()).limit(20).all()
        action_counts = {}
        for alert in recent:
            action = alert.action_taken or 'not_processed'
            action_counts[action] = action_counts.get(action, 0) + 1
        return {
            'enabled': str(get_setting('auto_response_enabled', 'false')).lower() == 'true',
            'threshold': int(get_setting('alert_threshold_level', '10')),
            'max_alert_age_seconds': int(get_setting('auto_response_max_alert_age_seconds', '600')),
            'polling_interval_seconds': int(get_setting('polling_interval_seconds', '60')),
            'whitelist_ips': get_setting('whitelist_ips', DEFAULT_WHITELIST),
            'scheduler_running': scheduler.running,
            'next_run_time': job.next_run_time.isoformat() if job and job.next_run_time else None,
            'last_run': get_setting('auto_response_last_run'),
            'last_status': get_setting('auto_response_last_status', 'never'),
            'last_summary': get_setting('auto_response_last_summary', '{}'),
            'last_error': get_setting('auto_response_last_error', ''),
            'recent_actions': action_counts,
            'latest_alerts': [{
                'id': item.id,
                'timestamp': item.timestamp,
                'rule_level': item.rule_level,
                'src_ip': item.src_ip,
                'action_taken': item.action_taken,
            } for item in recent[:5]],
        }, 200


@settings_ns.route('/test-wazuh')
class TestWazuh(Resource):
    method_decorators = [login_required]

    def post(self):
        """Test connection to Wazuh Manager and Indexer"""
        try:
            from app.services.wazuh_service import WazuhService
            wazuh = WazuhService()
            result = wazuh.test_connection()

            create_audit_log(
                action='test_connection',
                details=f"Wazuh connection test: {result.get('status')} - {result.get('message')}",
                performed_by=current_user.username,
                ip_address=request.remote_addr,
                result=result.get('status', 'failure')
            )

            status_code = 200 if result.get('status') == 'success' else 400
            return result, status_code
        except Exception as e:
            return {"status": "failure", "message": f"Wazuh connection error: {str(e)}"}, 500


@settings_ns.route('/test-pfsense')
class TestPfSense(Resource):
    method_decorators = [login_required]

    def post(self):
        """Test connection to pfSense REST API"""
        try:
            from app.services.pfsense_service import PfSenseService
            pfsense = PfSenseService()
            result = pfsense.test_connection()

            create_audit_log(
                action='test_connection',
                details=f"pfSense connection test: {result.get('status')} - {result.get('message')}",
                performed_by=current_user.username,
                ip_address=request.remote_addr,
                result=result.get('status', 'failure')
            )

            status_code = 200 if result.get('status') == 'success' else 400
            return result, status_code
        except Exception as e:
            return {"status": "failure", "message": f"pfSense connection error: {str(e)}"}, 500
