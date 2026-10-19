"""Mock-firewall simulation proving each SOC decision from Wazuh-shaped data."""

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock

from app import create_app
from app.extensions import db
from app.models import Alert
from app.services.response_engine import ResponseEngine
from app.utils.helpers import set_setting
from app.utils.threats import can_auto_block, classify_alert


class AttackMatrixTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing', start_scheduler=False)
        self.context = self.app.app_context()
        self.context.push()
        set_setting('auto_response_enabled', 'true')
        set_setting('alert_threshold_level', '10')
        self.engine = ResponseEngine()
        self.engine._pfsense_service = Mock()
        self.engine._pfsense_service.block_ip.return_value = {'status': 'success'}

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def alert(self, rule_id, groups, ip, level=12):
        return {
            'alert_id': f'case-{rule_id}', 'timestamp': datetime.now(timezone.utc).isoformat(),
            'rule_id': str(rule_id), 'rule_level': level,
            'rule_description': f'Rule {rule_id} test', 'rule_groups': json.dumps(groups),
            'agent_id': '001', 'agent_name': 'STIS', 'src_ip': ip,
            'dst_ip': None, 'src_port': None, 'dst_port': None,
            'full_log': '', 'raw_json': '{}',
        }

    def test_high_confidence_ip_alerts_are_blocked(self):
        cases = [
            (100401, ['webshell_probe'], '192.0.2.11'),
            (100430, ['sensitive_file'], '192.0.2.12'),
            (100440, ['rce'], '192.0.2.13'),
            (100460, ['path_traversal'], '192.0.2.14'),
            (100470, ['xss'], '192.0.2.15'),
            (100481, ['ssrf'], '192.0.2.31'),
            (31168, ['attack'], '192.0.2.16'),
            (100490, ['shellshock'], '192.0.2.18'),
            (100501, ['brute_force'], '192.0.2.17'),
            (100510, ['sql_injection'], '192.0.2.19'),
            (100600, ['ip_reputation', 'web_attack'], '192.0.2.25'),
        ]
        for rule_id, groups, ip in cases:
            with self.subTest(rule_id=rule_id):
                result = self.engine.evaluate_threat(self.alert(rule_id, groups, ip))
                self.assertTrue(result['block'])
        summary = self.engine.process_alerts([self.alert(*item) for item in cases])
        self.assertEqual(summary['blocked'], len(cases))
        self.assertEqual(self.engine._pfsense_service.block_ip.call_count, len(cases))
        self.assertEqual(Alert.query.count(), len(cases))

    def test_ambiguous_or_ipless_alerts_remain_investigations(self):
        cases = [
            (100400, ['webshell_probe'], '192.0.2.20', 7, 'below_threshold'),
            (100468, ['xss'], '192.0.2.26', 6, 'below_threshold'),
            (100469, ['xss'], '192.0.2.27', 6, 'below_threshold'),
            (31106, ['attack'], '192.0.2.28', 6, 'below_threshold'),
            (100480, ['ssrf'], '192.0.2.21', 12, 'review_only'),
            (100304, ['web_defacement'], None, 10, 'integrity_alert'),
            (100300, ['web_defacement'], '192.0.2.23', 12, 'integrity_alert'),
            (100305, ['webshell_content'], '192.0.2.24', 14, 'integrity_alert'),
            (99999, ['other'], '192.0.2.22', 15, 'review_only'),
            (100610, ['host_command'], None, 10, 'review_only'),
            (100611, ['suspicious_process'], None, 10, 'review_only'),
            (521, ['rootcheck'], None, 11, 'review_only'),
            (87105, ['virustotal'], None, 12, 'review_only'),
        ]
        for rule_id, groups, ip, level, expected in cases:
            with self.subTest(rule_id=rule_id):
                result = self.engine.evaluate_threat(self.alert(rule_id, groups, ip, level))
                self.assertEqual(result['action'], expected)
                self.assertFalse(result['block'])
        self.engine._pfsense_service.block_ip.assert_not_called()

    def test_linux_poc_findings_have_distinct_labels_and_safe_response(self):
        cases = [
            (100600, ['ip_reputation'], 'ip_reputation', True),
            (100610, ['host_command'], 'host_command', False),
            (100611, ['suspicious_process'], 'suspicious_process', False),
            (521, ['rootcheck'], 'rootkit', False),
            (87105, ['virustotal'], 'malware', False),
            (23504, ['vulnerability-detector'], 'host_vulnerability', False),
        ]
        for rule_id, groups, expected, blockable in cases:
            with self.subTest(rule_id=rule_id):
                alert = self.alert(rule_id, groups, '192.0.2.30')
                self.assertEqual(classify_alert(alert)['code'], expected)
                self.assertEqual(can_auto_block(alert), blockable)


if __name__ == '__main__':
    unittest.main()
