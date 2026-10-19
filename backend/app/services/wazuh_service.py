"""Read Manager inventory and Indexer alerts; normalize events for the SOC."""

import json
import logging
import re
import requests
import urllib3
from datetime import datetime, timedelta, timezone
from base64 import b64encode

# Lab certificates are self-signed; production TLS verification is separate.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class WazuhService:
    """Integration with Wazuh Manager API (port 55000) and Wazuh Indexer/OpenSearch (port 9200)."""

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self._token = None
        self._token_expiry = None

    def _get_config(self) -> dict:
        from app.utils.helpers import get_setting
        host = get_setting('wazuh_host', '127.0.0.1') or '127.0.0.1'
        clean_host = host.strip().replace("https://", "").replace("http://", "").rstrip("/")
        return {
            'wazuh_host': clean_host,
            'wazuh_api_port': get_setting('wazuh_api_port', '55000'),
            'wazuh_indexer_port': get_setting('wazuh_indexer_port', '9200'),
            'wazuh_api_user': get_setting('wazuh_api_user', 'wazuh'),
            'wazuh_api_password': get_setting('wazuh_api_password', ''),
            'wazuh_indexer_user': get_setting('wazuh_indexer_user', 'admin'),
            'wazuh_indexer_password': get_setting('wazuh_indexer_password', '')
        }

    def authenticate(self) -> str:
        config = self._get_config()
        url = f"https://{config['wazuh_host']}:{config['wazuh_api_port']}/security/user/authenticate?raw=true"
        auth_str = f"{config['wazuh_api_user']}:{config['wazuh_api_password']}"
        b64_auth = b64encode(auth_str.encode('utf-8')).decode('utf-8')
        headers = {
            'Authorization': f'Basic {b64_auth}'
        }

        try:
            response = self.session.post(url, headers=headers, timeout=10)
            response.raise_for_status()
            self._token = response.text.strip()
            # Cache token, set expiry to 14 minutes from now
            self._token_expiry = datetime.now(timezone.utc) + timedelta(minutes=14)
            return self._token
        except requests.RequestException as e:
            logger.error(f"Wazuh authentication failed: {e}")
            raise

    def _get_token(self) -> str:
        if self._token and self._token_expiry and datetime.now(timezone.utc) < self._token_expiry:
            return self._token
        return self.authenticate()

    def get_alerts(self, since: str = None, min_level: int = 1, max_results: int = 100) -> list[dict]:
        config = self._get_config()
        url = f"https://{config['wazuh_host']}:{config['wazuh_indexer_port']}/wazuh-alerts-*/_search"

        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"rule.level": {"gte": min_level}}}
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "asc" if since else "desc"}}],
            "size": max_results
        }

        if since:
            query["query"]["bool"]["filter"].append({"range": {"timestamp": {"gt": since}}})

        auth = (config['wazuh_indexer_user'], config['wazuh_indexer_password'])

        try:
            response = self.session.post(url, auth=auth, json=query, timeout=15)
            response.raise_for_status()
            data = response.json()
            hits = data.get('hits', {}).get('hits', [])

            return [self._parse_alert(hit) for hit in hits]
        except requests.RequestException as e:
            logger.error(f"Failed to fetch alerts from Wazuh Indexer: {e}")
            raise

    def _parse_alert(self, hit: dict) -> dict:
        source = hit.get('_source', {})
        rule = source.get('rule', {})
        agent = source.get('agent', {})
        data = source.get('data', {})

        # Extract IP and ports
        src_ip = data.get('srcip') or source.get('srcip') or data.get('src_ip')
        dst_ip = data.get('dstip') or source.get('dstip')
        src_port = data.get('srcport') or source.get('srcport')
        dst_port = data.get('dstport') or source.get('dstport')

        return {
            'alert_id': hit.get('_id'),
            'timestamp': source.get('timestamp'),
            'rule_id': str(rule.get('id', '')),
            'rule_description': rule.get('description', ''),
            'rule_level': rule.get('level', 0),
            'rule_groups': json.dumps(rule.get('groups', [])),
            'agent_id': str(agent.get('id', '')),
            'agent_name': agent.get('name', ''),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'full_log': source.get('full_log', ''),
            'raw_json': json.dumps(source)
        }

    def _manager_request(self, method: str, path: str, **kwargs):
        """Use the Manager JWT for read-only Agent inventory requests."""
        config = self._get_config()
        url = f"https://{config['wazuh_host']}:{config['wazuh_api_port']}{path}"
        headers = {'Authorization': f'Bearer {self._get_token()}'}
        headers.update(kwargs.pop('headers', {}))
        response = self.session.request(method, url, headers=headers, timeout=15, **kwargs)
        response.raise_for_status()
        return response.json() if response.content else {}

    def get_agent_inventory(self, agent_id: str) -> dict:
        """Read Wazuh's existing host inventory and live monitoring configuration.

        Each optional section is isolated so an older Agent or a missing RBAC
        permission does not hide the rest of the host inventory.
        """
        if not re.fullmatch(r'[0-9]{3,6}', str(agent_id)) or str(agent_id) == '000':
            raise ValueError('Invalid Wazuh Agent ID')
        agents = self.get_agents(raise_on_error=True)
        agent = next((item for item in agents if str(item.get('id')) == str(agent_id)), None)
        if agent is None:
            raise ValueError('Wazuh Agent was not found')

        result = {'agent': agent, 'sections': {}, 'errors': {}}
        paths = {
            'packages': f'/syscollector/{agent_id}/packages?limit=500',
            'services': f'/syscollector/{agent_id}/services?limit=500',
            'ports': f'/syscollector/{agent_id}/ports?limit=500',
            'log_sources': f'/agents/{agent_id}/config/logcollector/localfile',
            'file_integrity': f'/agents/{agent_id}/config/syscheck/syscheck',
        }
        for section, path in paths.items():
            try:
                payload = self._manager_request('GET', path).get('data', {})
                if section == 'log_sources' and isinstance(payload, dict):
                    payload = payload.get('localfile', payload.get('logcollector', payload))
                    if isinstance(payload, dict):
                        payload = payload.get('localfile', payload)
                elif section == 'file_integrity' and isinstance(payload, dict):
                    payload = payload.get('syscheck', payload)
                items = payload.get('affected_items') if isinstance(payload, dict) else payload
                if items is None:
                    items = [payload] if payload else []
                # Active configuration may be returned as a single object or
                # a list, depending on the Wazuh API version.
                if not isinstance(items, list):
                    items = [items]
                result['sections'][section] = {
                    'items': items,
                    'total': payload.get('total_affected_items', len(items))
                    if isinstance(payload, dict) else len(items),
                }
            except requests.RequestException as exc:
                result['errors'][section] = str(exc)
        return result

    def get_agents(self, *, raise_on_error: bool = False) -> list[dict]:
        try:
            token = self._get_token()
            config = self._get_config()
            url = f"https://{config['wazuh_host']}:{config['wazuh_api_port']}/agents?limit=1000"
            headers = {
                'Authorization': f'Bearer {token}'
            }

            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json().get('data', {}).get('affected_items', [])
        except requests.RequestException as e:
            logger.error(f"Failed to fetch Wazuh agents: {e}")
            if raise_on_error:
                raise
            return []

    def test_connection(self) -> dict:
        status = {"status": "success", "manager": False, "indexer": False, "message": ""}
        errors = []

        try:
            self.authenticate()
            status["manager"] = True
        except Exception as e:
            errors.append(f"Manager API error: {str(e)}")

        try:
            config = self._get_config()
            url = f"https://{config['wazuh_host']}:{config['wazuh_indexer_port']}/"
            auth = (config['wazuh_indexer_user'], config['wazuh_indexer_password'])
            response = self.session.get(url, auth=auth, timeout=5)
            response.raise_for_status()
            status["indexer"] = True
        except Exception as e:
            errors.append(f"Indexer error: {str(e)}")

        if not status["manager"] or not status["indexer"]:
            status["status"] = "failure"
            status["message"] = " | ".join(errors)
        else:
            status["message"] = "Connection successful to both Manager and Indexer."

        return status
