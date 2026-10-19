"""Uji kontrak alias, penerapan aturan, serta penanganan error firewall dengan HTTP mock."""

import unittest
from unittest.mock import Mock

from check_pfsense import run_write_test
from app.services.pfsense_service import PfSenseService


class PfSenseAliasTests(unittest.TestCase):
    def make_service(self):
        service = object.__new__(PfSenseService)
        service.alias_name = 'SOC_Blocklist'
        service.block_interface = 'wan'
        service.kill_states_on_block = False
        service._api_request = Mock()
        service.diagnose_block_rule = Mock(return_value={
            'readable': True,
            'found': True,
            'matches': [{'position': 1, 'id': 1}],
            'message': 'Found active WAN block rule',
        })
        return service

    def test_existing_alias_patch_uses_object_id(self):
        service = self.make_service()
        service._api_request.side_effect = [
            {'code': 200, 'data': [{'id': 7, 'name': 'SOC_Blocklist', 'address': ['198.51.100.1']}]},
            {'code': 200, 'data': {}},
            {'code': 200, 'data': {'applied': True}},
            {'code': 200, 'data': [{'id': 7, 'name': 'SOC_Blocklist', 'address': ['198.51.100.1', '198.51.100.2']}]},
        ]
        result = service.block_ip('198.51.100.2')
        self.assertEqual(result['status'], 'success')
        service._api_request.assert_any_call('PATCH', '/firewall/alias', {
            'id': 7, 'address': ['198.51.100.1', '198.51.100.2']
        })

    def test_new_alias_is_created_with_first_ip(self):
        service = self.make_service()
        service.ensure_blocklist_alias = Mock(return_value={
            'id': 8, 'name': 'SOC_Blocklist', 'address': ['198.51.100.2']
        })
        service._api_request.side_effect = [
            {'code': 200, 'data': []},
            {'code': 200, 'data': {'applied': True}},
            {'code': 200, 'data': [{'id': 8, 'name': 'SOC_Blocklist', 'address': ['198.51.100.2']}]},
        ]
        result = service.block_ip('198.51.100.2')
        self.assertEqual(result['status'], 'success')
        service.ensure_blocklist_alias.assert_called_once_with(initial_ip='198.51.100.2')

    def test_alias_read_failure_does_not_try_to_create_alias(self):
        service = self.make_service()
        service._api_request.return_value = {'status': 'error', 'message': '403 Forbidden'}
        result = service.block_ip('198.51.100.2')
        self.assertEqual(result['status'], 'error')
        self.assertIn('403', result['message'])
        service._api_request.assert_called_once_with('GET', '/firewall/aliases')

    def test_diagnosis_requires_alias_read_permission(self):
        service = self.make_service()
        service._api_request.side_effect = [
            {'code': 200, 'data': {'version': '2.8.1'}},
            {'status': 'error', 'message': '403 Client Error'},
        ]
        result = service.diagnose_connection()
        self.assertEqual(result['status'], 'failure')
        self.assertTrue(result['api'])
        self.assertFalse(result['alias_readable'])

    def test_diagnosis_reports_required_alias(self):
        service = self.make_service()
        service.diagnose_block_rule = PfSenseService.diagnose_block_rule.__get__(service)
        service._api_request.side_effect = [
            {'code': 200, 'data': {'version': '2.8.1'}},
            {'code': 200, 'data': [{'id': 3, 'name': 'SOC_Blocklist', 'address': []}]},
            {'code': 200, 'data': [{
                'id': 1, 'type': 'block', 'interface': ['wan'],
                'src': 'SOC_Blocklist', 'descr': 'STIS SOC blocklist',
            }]},
        ]
        result = service.diagnose_connection()
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['alias_readable'])
        self.assertTrue(result['alias_exists'])
        self.assertTrue(result['block_rule_found'])

    def test_diagnosis_warns_when_alias_has_no_wan_block_rule(self):
        service = self.make_service()
        service.block_interface = 'wan'
        service.diagnose_block_rule = PfSenseService.diagnose_block_rule.__get__(service)
        service._api_request.side_effect = [
            {'code': 200, 'data': {'version': '2.8.1'}},
            {'code': 200, 'data': [{'id': 3, 'name': 'SOC_Blocklist', 'address': []}]},
            {'code': 200, 'data': [{
                'id': 2, 'type': 'pass', 'interface': ['wan'],
                'src': 'any', 'descr': 'HAProxy pass',
            }]},
        ]

        result = service.diagnose_connection()

        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['block_rule_found'])
        self.assertIn('No enabled wan block rule', result['message'])

    def test_successful_block_clears_matching_active_states(self):
        service = self.make_service()
        service.kill_states_on_block = True
        service._api_request.side_effect = [
            {'code': 200, 'data': [{'id': 7, 'name': 'SOC_Blocklist', 'address': []}]},
            {'code': 200, 'data': {}},
            {'code': 200, 'data': {'applied': True}},
            {'code': 200, 'data': [{'id': 7, 'name': 'SOC_Blocklist', 'address': ['192.168.18.103']}]},
            {'code': 200, 'data': [{'id': 42}]},
        ]

        result = service.block_ip('192.168.18.103')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['state_cleanup']['status'], 'success')
        service._api_request.assert_called_with(
            'DELETE',
            '/firewall/states',
            params={'source__regex': r'^192\.168\.18\.103(?::|$)'},
        )

    def test_apply_success_without_alias_entry_is_reported_as_failure(self):
        service = self.make_service()
        service._api_request.side_effect = [
            {'code': 200, 'data': [{'id': 7, 'name': 'SOC_Blocklist', 'address': []}]},
            {'code': 200, 'data': {}},
            {'code': 200, 'data': {'applied': True}},
            {'code': 200, 'data': [{'id': 7, 'name': 'SOC_Blocklist', 'address': []}]},
        ]

        result = service.block_ip('192.168.18.103')

        self.assertEqual(result['status'], 'error')
        self.assertIn('not present in alias', result['message'])

    def test_alias_membership_without_active_rule_is_not_reported_as_blocked(self):
        service = self.make_service()
        service._api_request.return_value = {
            'code': 200,
            'data': [{
                'id': 7, 'name': 'SOC_Blocklist',
                'address': ['192.168.18.103'],
            }],
        }
        service.diagnose_block_rule.return_value = {
            'readable': True,
            'found': False,
            'matches': [],
            'message': 'No enabled wan block rule uses alias SOC_Blocklist.',
        }

        result = service.block_ip('192.168.18.103')

        self.assertEqual(result['status'], 'error')
        self.assertIn('no enabled wan Block/Reject rule', result['message'])

    def test_unreadable_firewall_rules_are_not_reported_as_enforced(self):
        service = self.make_service()
        service._api_request.return_value = {
            'code': 200,
            'data': [{
                'id': 7, 'name': 'SOC_Blocklist',
                'address': ['192.168.18.103'],
            }],
        }
        service.diagnose_block_rule.return_value = {
            'readable': False,
            'found': False,
            'message': '403 missing GET firewall rules privilege',
        }

        result = service.block_ip('192.168.18.103')

        self.assertEqual(result['status'], 'error')
        self.assertIn('could not be verified', result['message'])

    def test_unblock_is_verified_absent_from_alias(self):
        service = self.make_service()
        service._api_request.side_effect = [
            {'code': 200, 'data': [{
                'id': 7, 'name': 'SOC_Blocklist',
                'address': ['192.168.18.103', '198.51.100.1'],
            }]},
            {'code': 200, 'data': {}},
            {'code': 200, 'data': {'applied': True}},
            {'code': 200, 'data': [{
                'id': 7, 'name': 'SOC_Blocklist',
                'address': ['198.51.100.1'],
            }]},
        ]

        result = service.unblock_ip('192.168.18.103')

        self.assertEqual(result['status'], 'success')

    def test_unblock_apply_without_removal_is_reported_as_failure(self):
        service = self.make_service()
        service._api_request.side_effect = [
            {'code': 200, 'data': [{
                'id': 7, 'name': 'SOC_Blocklist',
                'address': ['192.168.18.103'],
            }]},
            {'code': 200, 'data': {}},
            {'code': 200, 'data': {'applied': True}},
            {'code': 200, 'data': [{
                'id': 7, 'name': 'SOC_Blocklist',
                'address': ['192.168.18.103'],
            }]},
        ]

        result = service.unblock_ip('192.168.18.103')

        self.assertEqual(result['status'], 'error')
        self.assertIn('still present in alias', result['message'])

    def test_reversible_write_diagnostic_blocks_and_cleans_up(self):
        service = Mock()
        service.get_blocked_ips.return_value = []
        service.block_ip.return_value = {'status': 'success', 'message': 'blocked'}
        service.unblock_ip.return_value = {'status': 'success', 'message': 'unblocked'}
        result = {'status': 'success'}

        run_write_test(service, result, '198.51.100.254')

        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['write_test']['status'], 'success')
        service.block_ip.assert_called_once_with(
            '198.51.100.254', 'STIS SOC reversible integration test'
        )
        service.unblock_ip.assert_called_once_with('198.51.100.254')

    def test_write_diagnostic_reports_patch_failure(self):
        service = Mock()
        service.get_blocked_ips.return_value = []
        service.block_ip.return_value = {
            'status': 'error', 'message': '403 missing PATCH privilege'
        }
        result = {'status': 'success'}

        run_write_test(service, result, '198.51.100.254')

        self.assertEqual(result['status'], 'failure')
        self.assertIn('403', result['write_test']['block']['message'])
        service.unblock_ip.assert_not_called()


if __name__ == '__main__':
    unittest.main()
