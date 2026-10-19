"""Read-only diagnosis for SQL Injection detection and response readiness."""
import argparse
import json
import sys

from app import create_app
from app.models import Alert
from app.services.response_engine import ResponseEngine
from app.services.wazuh_service import WazuhService
from app.utils.helpers import DEFAULT_WHITELIST, get_setting
from app.utils.threats import classify_alert


def parse_args():
    parser = argparse.ArgumentParser(
        description='Check recent SQL Injection alerts without changing pfSense.'
    )
    parser.add_argument('--limit', type=int, default=100, help='Recent Wazuh alerts to inspect.')
    return parser.parse_args()


def summarize(alert, decision=None):
    result = {
        'alert_id': alert.get('alert_id'),
        'timestamp': alert.get('timestamp'),
        'rule_id': alert.get('rule_id'),
        'level': alert.get('rule_level'),
        'src_ip': alert.get('src_ip'),
        'description': alert.get('rule_description'),
    }
    if decision:
        result['decision_now'] = decision.get('action')
    return result


def main():
    args = parse_args()
    app = create_app(start_scheduler=False)
    with app.app_context():
        engine = ResponseEngine()
        result = {
            'status': 'success',
            'configuration': {
                'auto_response_enabled': str(
                    get_setting('auto_response_enabled', 'false')
                ).lower() == 'true',
                'threshold': int(get_setting('alert_threshold_level', '10')),
                'max_alert_age_seconds': int(
                    get_setting('auto_response_max_alert_age_seconds', '600')
                ),
                'whitelist_ips': get_setting('whitelist_ips', DEFAULT_WHITELIST),
                'supported_rule_ids': ['31103', '100200', '100201', '100202', '100510'],
            },
        }

        recent_db = Alert.query.order_by(Alert.id.desc()).limit(500).all()
        result['soc_sql_injection_alerts'] = [
            {
                **summarize(alert.to_dict()),
                'action_taken': alert.action_taken,
            }
            for alert in recent_db
            if classify_alert(alert)['code'] == 'sql_injection'
        ][:10]

        try:
            wazuh_alerts = WazuhService().get_alerts(
                min_level=1,
                max_results=max(1, min(args.limit, 1000)),
            )
            sqli_alerts = [
                alert for alert in wazuh_alerts
                if classify_alert(alert)['code'] == 'sql_injection'
            ]
            result['wazuh_sql_injection_alerts'] = [
                summarize(alert, engine.evaluate_threat(alert))
                for alert in sqli_alerts[:10]
            ]
            result['message'] = (
                f"Found {len(sqli_alerts)} SQL Injection alert(s) among "
                f"the latest {len(wazuh_alerts)} Wazuh alert(s)."
            )
        except Exception as error:
            result['status'] = 'failure'
            result['wazuh_error'] = str(error)
            result['message'] = 'Could not read alerts from the Wazuh Indexer.'

        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'success' else 1


if __name__ == '__main__':
    sys.exit(main())
