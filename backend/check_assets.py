"""Read-only diagnosis of legacy SOC rows and live Wazuh Agent enrollment.

Run from the backend directory with: venv/bin/python check_assets.py
No passwords or integration settings are printed.
"""

import json

from app import create_app
from app.extensions import db
from app.models import MonitoredAsset, MonitoredServer
from app.services.wazuh_service import WazuhService


def main():
    app = create_app(start_scheduler=False)
    with app.app_context():
        servers = MonitoredServer.query.order_by(MonitoredServer.agent_id).all()
        assets = MonitoredAsset.query.order_by(MonitoredAsset.agent_id, MonitoredAsset.name).all()
        report = {
            'database': db.engine.url.database,
            # These rows are archival after dashboard CRUD removal; they do
            # not configure Agent collection or Manager groups anymore.
            'soc_servers': [server.to_dict() for server in servers],
            'soc_resources': [asset.to_dict() for asset in assets],
            'wazuh_agents': [],
        }
        try:
            report['wazuh_agents'] = [
                {key: agent.get(key) for key in ('id', 'name', 'status', 'ip', 'group')}
                for agent in WazuhService().get_agents(raise_on_error=True)
                if str(agent.get('id')) != '000'
            ]
        except Exception as exc:
            report['wazuh_error'] = str(exc)
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))


if __name__ == '__main__':
    main()
