"""Read-only Wazuh Agent inventory for the SOC dashboard.

Enrollment and log/FIM configuration now live on each monitored host. No
endpoint in this namespace writes to the Manager or to legacy SOC asset tables.
"""

from flask_login import login_required
from flask_restx import Namespace, Resource
from requests import RequestException

from app.services.wazuh_service import WazuhService


assets_ns = Namespace('assets', description='Read-only Wazuh Agent inventory')


@assets_ns.route('/agents')
class AssetAgents(Resource):
    method_decorators = [login_required]

    def get(self):
        try:
            agents = WazuhService().get_agents(raise_on_error=True)
            return {'items': [
                {key: item.get(key) for key in
                 ('id', 'name', 'status', 'ip', 'os', 'version', 'group', 'group_config_status')}
                for item in agents if str(item.get('id')) != '000'
            ]}, 200
        except RequestException as exc:
            return {'message': f'Wazuh Agent API unavailable: {exc}'}, 502


@assets_ns.route('/agents/<string:agent_id>/inventory')
class AssetAgentInventory(Resource):
    method_decorators = [login_required]

    def get(self, agent_id):
        try:
            return WazuhService().get_agent_inventory(agent_id), 200
        except ValueError as exc:
            return {'message': str(exc)}, 404
        except RequestException as exc:
            return {'message': f'Wazuh Agent API unavailable: {exc}'}, 502
