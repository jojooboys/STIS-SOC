"""Read-only pfSense diagnosis with an optional reversible alias write test."""
import argparse
import json
import sys

from app import create_app
from app.services.pfsense_service import PfSenseService


def parse_args():
    parser = argparse.ArgumentParser(description='Diagnose the STIS SOC pfSense integration.')
    parser.add_argument(
        '--write-test', action='store_true',
        help='Temporarily add and remove a documentation IP to test alias write/apply permissions.'
    )
    parser.add_argument(
        '--test-ip', default='198.51.100.254',
        help='IPv4 address used by --write-test (default: 198.51.100.254).'
    )
    return parser.parse_args()


def run_write_test(service, result, test_ip):
    if result.get('status') != 'success':
        result['write_test'] = {
            'status': 'skipped',
            'message': 'Read-only diagnosis failed; write test was not attempted.'
        }
        return

    existing = set(service.get_blocked_ips())
    if test_ip in existing:
        result['status'] = 'failure'
        result['write_test'] = {
            'status': 'failure',
            'test_ip': test_ip,
            'message': 'Test IP already exists in the alias; it was not modified.'
        }
        return

    block_result = service.block_ip(test_ip, 'STIS SOC reversible integration test')
    if block_result.get('status') != 'success':
        result['status'] = 'failure'
        result['write_test'] = {
            'status': 'failure',
            'test_ip': test_ip,
            'block': block_result,
            'message': 'Could not add/apply the test IP.'
        }
        return

    unblock_result = service.unblock_ip(test_ip)
    if unblock_result.get('status') != 'success':
        result['status'] = 'failure'
        result['write_test'] = {
            'status': 'failure',
            'test_ip': test_ip,
            'block': block_result,
            'unblock': unblock_result,
            'message': f'Block succeeded but cleanup failed; remove {test_ip} from the alias manually.'
        }
        return

    result['write_test'] = {
        'status': 'success',
        'test_ip': test_ip,
        'block': block_result,
        'unblock': unblock_result,
        'message': 'Alias PATCH and firewall apply succeeded; the test IP was removed.'
    }


def main():
    args = parse_args()
    app = create_app(start_scheduler=False)
    with app.app_context():
        service = PfSenseService()
        result = service.diagnose_connection()
        if args.write_test:
            run_write_test(service, result, args.test_ip)
        print(json.dumps(result, indent=2))
        return 0 if result.get('status') == 'success' else 1


if __name__ == '__main__':
    sys.exit(main())
