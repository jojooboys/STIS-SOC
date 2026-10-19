"""Read-only diagnosis for website defacement/content-injection alerts."""
import argparse
import json
import sys

from app import create_app
from app.models import Alert
from app.services.response_engine import ResponseEngine
from app.services.wazuh_service import WazuhService
from app.utils.threats import classify_alert


def parse_args():
    parser = argparse.ArgumentParser(
        description='Check recent web-defacement alerts without changing pfSense.'
    )
    parser.add_argument('--limit', type=int, default=100, help='Recent Wazuh alerts to inspect.')
    return parser.parse_args()


def summarize(alert, decision=None):
    result = {
        'alert_id': alert.get('alert_id'),
        'timestamp': alert.get('timestamp'),
        'rule_id': alert.get('rule_id'),
        'level': alert.get('rule_level'),
        'agent': alert.get('agent_name'),
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
            'supported_rule_ids': ['100300', '100301', '100302', '100304'],
        }

        recent_db = Alert.query.order_by(Alert.id.desc()).limit(500).all()
        result['soc_web_defacement_alerts'] = [
            {
                **summarize(alert.to_dict()),
                'action_taken': alert.action_taken,
            }
            for alert in recent_db
            if classify_alert(alert)['code'] == 'web_defacement'
        ][:10]

        try:
            wazuh_alerts = WazuhService().get_alerts(
                min_level=1,
                max_results=max(1, min(args.limit, 1000)),
            )
            matches = [
                alert for alert in wazuh_alerts
                if classify_alert(alert)['code'] == 'web_defacement'
            ]
            result['wazuh_web_defacement_alerts'] = [
                summarize(alert, engine.evaluate_threat(alert))
                for alert in matches[:10]
            ]
            result['message'] = (
                f"Found {len(matches)} web-defacement alert(s) among "
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
