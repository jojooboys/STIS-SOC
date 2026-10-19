"""Run from backend: python check_wazuh.py. No alert processing or IP blocking."""
import json
import sys

from app import create_app
from app.services.wazuh_service import WazuhService


def main():
    app = create_app(start_scheduler=False)
    with app.app_context():
        service = WazuhService()
        result = service.test_connection()
        result['alerts_readable'] = False
        try:
            alerts = service.get_alerts(max_results=1)
            result['alerts_readable'] = True
            result['sample_count'] = len(alerts)
        except Exception as error:
            result['status'] = 'failure'
            result['alerts_error'] = str(error)
            result['message'] += ' Alert search failed; see alerts_error.'
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'success' else 1


if __name__ == '__main__':
    sys.exit(main())
