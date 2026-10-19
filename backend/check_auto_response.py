"""Read-only diagnosis for the STIS SOC automatic response pipeline."""
import json
import sys

from app import create_app
from app.models import Alert
from app.services.pfsense_service import PfSenseService
from app.services.response_engine import ResponseEngine
from app.services.wazuh_service import WazuhService
from app.utils.helpers import DEFAULT_WHITELIST, get_setting


def main():
    app = create_app(start_scheduler=False)
    with app.app_context():
        enabled = str(get_setting('auto_response_enabled', 'false')).lower() == 'true'
        threshold = int(get_setting('alert_threshold_level', '10'))
        max_age = int(get_setting('auto_response_max_alert_age_seconds', '600'))
        result = {
            'status': 'success',
            'configuration': {
                'enabled': enabled,
                'threshold': threshold,
                'polling_interval_seconds': int(get_setting('polling_interval_seconds', '60')),
                'max_alert_age_seconds': max_age,
                'whitelist_ips': get_setting('whitelist_ips', DEFAULT_WHITELIST),
                'kill_pfsense_states_on_block': str(
                    get_setting('pfsense_kill_states_on_block', 'true')
                ).lower() == 'true',
            },
            'scheduler': {
                'last_run': get_setting('auto_response_last_run'),
                'last_status': get_setting('auto_response_last_status', 'never'),
                'last_summary': get_setting('auto_response_last_summary', '{}'),
                'last_error': get_setting('auto_response_last_error', ''),
                'checkpoint': get_setting('last_fetch_timestamp'),
            },
        }

        recent = Alert.query.order_by(Alert.id.desc()).limit(10).all()
        result['recent_database_alerts'] = [{
            'timestamp': alert.timestamp,
            'level': alert.rule_level,
            'src_ip': alert.src_ip,
            'action': alert.action_taken,
            'description': alert.rule_description,
        } for alert in recent]

        try:
            alerts = WazuhService().get_alerts(min_level=threshold, max_results=5)
            engine = ResponseEngine()
            result['latest_wazuh_alerts'] = [{
                'timestamp': alert.get('timestamp'),
                'level': alert.get('rule_level'),
                'src_ip': alert.get('src_ip'),
                'decision_now': engine.evaluate_threat(alert).get('action'),
                'description': alert.get('rule_description'),
            } for alert in alerts]
            result['wazuh_indexer_readable'] = True
        except Exception as error:
            result['wazuh_indexer_readable'] = False
            result['wazuh_error'] = str(error)
            result['status'] = 'failure'

        pfsense = PfSenseService().diagnose_connection()
        result['pfsense'] = pfsense
        if pfsense.get('status') != 'success' or not enabled:
            result['status'] = 'failure'

        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'success' else 1


if __name__ == '__main__':
    sys.exit(main())
