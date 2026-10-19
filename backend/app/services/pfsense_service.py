"""Read and update the pfSense blocklist alias through REST API v2."""

import logging
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class PfSenseService:
    """Integration with pfSense REST API v2 using alias-based IP blocking."""

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        config = self._get_config()
        self.pfsense_host = config.get('pfsense_host', '')
        self.pfsense_api_key = config.get('pfsense_api_key', '')
        self.alias_name = config.get('pfsense_alias_name', 'SOC_Blocklist')
        self.block_interface = config.get('pfsense_block_interface', 'wan')
        self.kill_states_on_block = str(
            config.get('pfsense_kill_states_on_block', 'true')
        ).lower() == 'true'

        self.session.headers.update({
            'X-API-Key': self.pfsense_api_key,
            'Content-Type': 'application/json'
        })

    def _get_config(self) -> dict:
        from app.utils.helpers import get_setting
        return {
            'pfsense_host': get_setting('pfsense_host', '10.10.10.1'),
            'pfsense_api_key': get_setting('pfsense_api_key', ''),
            'pfsense_alias_name': get_setting('pfsense_alias_name', 'SOC_Blocklist'),
            'pfsense_block_interface': get_setting('pfsense_block_interface', 'wan'),
            'pfsense_kill_states_on_block': get_setting('pfsense_kill_states_on_block', 'true'),
        }

    def _api_request(
        self,
        method: str,
        endpoint: str,
        data: dict = None,
        params: dict = None,
    ) -> dict:
        if not self.pfsense_host:
            logger.error("pfSense host is not configured.")
            return {"status": "error", "message": "pfSense host not configured"}

        host = self.pfsense_host.strip()
        if host.startswith("https://") or host.startswith("http://"):
            base_url = host.rstrip("/")
        else:
            base_url = f"https://{host.rstrip('/')}"

        url = f"{base_url}/api/v2{endpoint}"
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, params=params, timeout=10)
            elif method.upper() == 'PATCH':
                response = self.session.patch(url, json=data, params=params, timeout=10)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, json=data, params=params, timeout=10)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            logger.info(f"pfSense API {method} {endpoint} - Status {response.status_code}")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"pfSense API request failed: {method} {endpoint} - Error: {e}")
            if e.response is not None:
                try:
                    details = e.response.json()
                    api_message = details.get('message') if isinstance(details, dict) else None
                    message = str(e)
                    if api_message:
                        message = f"{message} - pfSense: {api_message}"
                    return {"status": "error", "message": message, "details": details}
                except Exception:
                    return {"status": "error", "message": str(e), "details": e.response.text}
            return {"status": "error", "message": str(e)}

    def kill_states(self, ip_address: str) -> dict:
        """Terminate active firewall states whose source is the blocked IP."""
        escaped_ip = re.escape(ip_address)
        result = self._api_request(
            'DELETE',
            '/firewall/states',
            params={'source__regex': rf'^{escaped_ip}(?::|$)'},
        )
        if result and result.get('code') == 200:
            deleted = result.get('data', [])
            count = len(deleted) if isinstance(deleted, list) else None
            message = f"Active states for {ip_address} were cleared"
            if count is not None:
                message += f" ({count} state(s))"
            return {"status": "success", "message": message, "deleted": count}
        return {
            "status": "error",
            "message": (result or {}).get('message', 'Could not clear active pfSense states'),
        }

    def _successful_block_result(self, ip_address: str, message: str) -> dict:
        """Verify enforcement, then return success and clear active states."""
        rule_check = self.diagnose_block_rule()
        if not rule_check.get('readable'):
            return {
                "status": "error",
                "message": (
                    f"IP {ip_address} is in alias {self.alias_name}, but the active "
                    f"firewall rule could not be verified: {rule_check.get('message')}"
                ),
                "block_rule": rule_check,
            }
        if not rule_check.get('found'):
            return {
                "status": "error",
                "message": (
                    f"IP {ip_address} is in alias {self.alias_name}, but no enabled "
                    f"{self.block_interface} Block/Reject rule uses that alias"
                ),
                "block_rule": rule_check,
            }

        result = {
            "status": "success",
            "message": message,
            "block_rule": rule_check,
        }
        if not getattr(self, 'kill_states_on_block', False):
            return result

        cleanup = self.kill_states(ip_address)
        result['state_cleanup'] = cleanup
        if cleanup.get('status') != 'success':
            logger.warning(
                "IP %s is in the pfSense block alias, but active states could not be cleared: %s",
                ip_address,
                cleanup.get('message'),
            )
        return result

    def _verified_block_result(self, ip_address: str, message: str) -> dict:
        """Confirm a write is visible in the alias before reporting success."""
        verification = self.read_blocklist()
        if verification.get('status') != 'success':
            return {
                "status": "error",
                "message": (
                    f"pfSense apply returned success, but {self.alias_name} "
                    f"could not be verified: {verification.get('message', 'unknown error')}"
                ),
            }
        if ip_address not in verification.get('addresses', []):
            return {
                "status": "error",
                "message": (
                    f"pfSense apply returned success, but IP {ip_address} "
                    f"is not present in alias {self.alias_name}"
                ),
            }
        return self._successful_block_result(ip_address, message)

    def _verified_unblock_result(self, ip_address: str) -> dict:
        """Confirm the IP is absent from the alias before reporting success."""
        verification = self.read_blocklist()
        if verification.get('status') != 'success':
            return {
                "status": "error",
                "message": (
                    f"pfSense apply returned success, but {self.alias_name} "
                    f"could not be verified: {verification.get('message', 'unknown error')}"
                ),
            }
        if ip_address in verification.get('addresses', []):
            return {
                "status": "error",
                "message": (
                    f"pfSense apply returned success, but IP {ip_address} "
                    f"is still present in alias {self.alias_name}"
                ),
            }
        return {"status": "success", "message": f"Unblocked IP {ip_address}"}

    def get_aliases(self) -> list[dict]:
        res = self._api_request('GET', '/firewall/aliases')
        if res and res.get('code') == 200:
            return res.get('data', [])
        return []

    def read_blocklist(self) -> dict:
        """Read the configured alias without mistaking an API error for an empty list."""
        res = self._api_request('GET', '/firewall/aliases')
        if not res or res.get('code') != 200:
            return {"status": "error", "message": (res or {}).get('message', 'Cannot read pfSense aliases')}
        aliases = res.get('data')
        if not isinstance(aliases, list):
            return {"status": "error", "message": "Invalid pfSense aliases response"}
        alias = next((item for item in aliases if item.get('name') == self.alias_name), None)
        if alias is None:
            return {"status": "error", "message": f"Alias {self.alias_name} does not exist on pfSense"}
        addresses = alias.get('address', [])
        if not isinstance(addresses, list):
            return {"status": "error", "message": f"Alias {self.alias_name} has invalid address data"}
        return {"status": "success", "alias": alias, "addresses": addresses}

    def get_alias_by_name(self, name: str) -> dict | None:
        aliases = self.get_aliases()
        for alias in aliases:
            if alias.get('name') == name:
                return alias
        return None

    def ensure_blocklist_alias(self, initial_ip: str = None) -> dict:
        alias = self.get_alias_by_name(self.alias_name)
        if alias:
            return alias

        data = {
            "name": self.alias_name,
            "type": "host",
            "descr": "SOC Auto-Blocklist",
            "address": [initial_ip] if initial_ip else []
        }
        res = self._api_request('POST', '/firewall/alias', data)
        if res.get('code') == 200:
            return res.get('data', {})
        return res

    def block_ip(self, ip_address: str, reason: str = '') -> dict:
        aliases_res = self._api_request('GET', '/firewall/aliases')
        if not aliases_res or aliases_res.get('code') != 200:
            return {"status": "error", "message": (aliases_res or {}).get('message', 'Cannot read pfSense aliases')}
        aliases = aliases_res.get('data')
        if not isinstance(aliases, list):
            return {"status": "error", "message": "Invalid pfSense aliases response"}
        alias = next((item for item in aliases if item.get('name') == self.alias_name), None)
        if alias is None:
            alias = self.ensure_blocklist_alias(initial_ip=ip_address)
            if alias and alias.get('status') == 'error':
                return alias
            apply_result = self._api_request('POST', '/firewall/apply')
            if apply_result.get('code') == 200:
                return self._verified_block_result(
                    ip_address,
                    f"Created {self.alias_name} and blocked IP {ip_address}",
                )
            return apply_result

        addresses = alias.get('address', [])
        if not isinstance(addresses, list):
            return {"status": "error", "message": "Invalid pfSense alias address data"}
        addresses = list(addresses)
        if ip_address in addresses:
            return self._successful_block_result(
                ip_address,
                f"IP {ip_address} already in blocklist",
            )

        addresses.append(ip_address)

        data = {
            "id": alias.get('id'),
            "address": addresses
        }

        if data['id'] is None:
            return {"status": "error", "message": f"Alias {self.alias_name} has no REST API object ID"}

        res = self._api_request('PATCH', '/firewall/alias', data)
        if res.get('code') == 200:
            apply_result = self._api_request('POST', '/firewall/apply')
            if apply_result.get('code') == 200:
                return self._verified_block_result(ip_address, f"Blocked IP {ip_address}")
            return apply_result
        return res

    def unblock_ip(self, ip_address: str) -> dict:
        blocklist = self.read_blocklist()
        if blocklist['status'] != 'success':
            return blocklist
        alias = blocklist['alias']

        addresses = list(blocklist['addresses'])
        if ip_address not in addresses:
            return {"status": "success", "message": f"IP {ip_address} not in blocklist"}

        addresses.remove(ip_address)

        data = {
            "id": alias.get('id'),
            "address": addresses
        }

        if data['id'] is None:
            return {"status": "error", "message": f"Alias {self.alias_name} has no REST API object ID"}

        res = self._api_request('PATCH', '/firewall/alias', data)
        if res.get('code') == 200:
            apply_result = self._api_request('POST', '/firewall/apply')
            if apply_result.get('code') == 200:
                return self._verified_unblock_result(ip_address)
            return apply_result
        return res

    def get_blocked_ips(self) -> list[str]:
        alias = self.get_alias_by_name(self.alias_name)
        if alias:
            return alias.get('address', [])
        return []

    def get_firewall_rules(self) -> list[dict]:
        res = self._api_request('GET', '/firewall/rules')
        if res and res.get('code') == 200:
            return res.get('data', [])
        return []

    @staticmethod
    def _rule_contains_value(value, expected: str) -> bool:
        if isinstance(value, dict):
            return any(
                PfSenseService._rule_contains_value(item, expected)
                for item in value.values()
            )
        if isinstance(value, (list, tuple, set)):
            return any(
                PfSenseService._rule_contains_value(item, expected)
                for item in value
            )
        return str(value or '').strip().lower() == expected.strip().lower()

    def diagnose_block_rule(self) -> dict:
        """Check whether an enabled block rule references the configured alias."""
        response = self._api_request('GET', '/firewall/rules')
        if not response or response.get('code') != 200:
            return {
                'readable': False,
                'found': False,
                'message': (response or {}).get(
                    'message', 'Cannot read pfSense firewall rules'
                ),
            }

        rules = response.get('data', [])
        matches = []
        for position, rule in enumerate(rules, start=1):
            rule_type = str(rule.get('type') or rule.get('action') or '').lower()
            disabled = str(rule.get('disabled', 'false')).lower() in ('true', '1', 'yes')
            source = rule.get('src', rule.get('source'))
            interface = rule.get('interface', rule.get('interfaces'))
            if (
                rule_type in ('block', 'reject')
                and not disabled
                and self._rule_contains_value(source, self.alias_name)
                and self._rule_contains_value(interface, self.block_interface)
            ):
                matches.append({
                    'position': position,
                    'id': rule.get('id'),
                    'description': rule.get('descr') or rule.get('description'),
                    'type': rule_type,
                    'interface': interface,
                    'source': source,
                })

        return {
            'readable': True,
            'found': bool(matches),
            'matches': matches,
            'message': (
                f"Found {len(matches)} enabled {self.block_interface} block rule(s) "
                f"using alias {self.alias_name}."
                if matches else
                f"No enabled {self.block_interface} block rule uses alias {self.alias_name}."
            ),
        }

    def test_connection(self) -> dict:
        return self.diagnose_connection()

    def diagnose_connection(self) -> dict:
        """Check API authentication and alias-read permission without changing pfSense."""
        version_res = self._api_request('GET', '/system/version')
        if not version_res or version_res.get('code') != 200:
            return {
                "status": "failure",
                "api": False,
                "alias_readable": False,
                "alias_exists": False,
                "message": version_res.get('message', 'Failed to connect') if version_res else 'Empty API response'
            }

        aliases_res = self._api_request('GET', '/firewall/aliases')
        if not aliases_res or aliases_res.get('code') != 200:
            return {
                "status": "failure",
                "api": True,
                "alias_readable": False,
                "alias_exists": False,
                "message": aliases_res.get('message', 'Connected, but cannot read firewall aliases') if aliases_res else 'Empty aliases response'
            }

        aliases = aliases_res.get('data', [])
        alias_exists = any(item.get('name') == self.alias_name for item in aliases)
        message = "Connected to pfSense API and firewall aliases are readable."
        if not alias_exists:
            message += f" Alias {self.alias_name} does not exist yet."
        rule_check = self.diagnose_block_rule()
        if not rule_check.get('found'):
            message += f" Warning: {rule_check.get('message')}"

        return {
            "status": "success",
            "api": True,
            "alias_readable": True,
            "alias_exists": alias_exists,
            "alias_name": self.alias_name,
            "aliases_count": len(aliases),
            "block_rule_readable": rule_check.get('readable', False),
            "block_rule_found": rule_check.get('found', False),
            "block_rule_matches": rule_check.get('matches', []),
            "version": version_res.get('data', {}).get('version'),
            "message": message
        }
