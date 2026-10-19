"""Exercise installed Wazuh decoders/rules with safe, synthetic lab log lines.

Run on UbuntuServer after installing local_rules.xml and local_decoder.xml.
This checks Wazuh's actual rule engine. It does not insert production alerts,
call pfSense, or claim that an application exploit succeeded.
"""

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


LOGTEST = '/var/ossec/bin/wazuh-logtest'
IP = '198.51.100.77'  # Documentation-only address; never a real attacker.
JSON_TIMESTAMP = '2026-10-02T10:00:00Z'


def apache(url, *, status=404, user_agent='STIS-SOC-test', src_ip=IP):
    return (f'{src_ip} - - [02/Oct/2026:10:00:00 +0700] '
            f'"GET {url} HTTP/1.1" {status} 123 "-" "{user_agent}"')


def structured_event(**fields):
    """Match the JSONL shape emitted by lab_probe.php and Website Guard."""
    return json.dumps({'timestamp': JSON_TIMESTAMP, **fields})


CASES = [
    ('webshell_probe', '100401', [apache('/radio.php')] * 5),
    ('wordpress_scan', '100411', [apache('/wp-login.php')] * 8),
    ('vulnerability_scan', '100421', [apache('/not-found', user_agent='nuclei/3.0')] * 10),
    ('sensitive_file', '100430', [apache('/.env')]),
    ('rce', '100440', [apache('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php')]),
    ('recon', '100451', [apache('/manager/html')] * 5),
    ('path_traversal', '100460', [apache('/download?file=%2e%2e%2fetc%2fpasswd')]),
    ('xss_404', '100470', [apache('/?q=%3Cscript%3Ealert(1)%3C/script%3E')] * 5),
    ('xss_200', '100470', [apache('/?q=%3Cscript%3Ealert(1)%3C/script%3E', status=200)] * 5),
    ('ssrf', '100480', [apache('/fetch?url=http%3A%2F%2F169.254.169.254%2F')]),
    ('ssrf_repeated', '100481', [apache('/stis-soc-test-ssrf?url=http%3A%2F%2F127.0.0.1%3A9%2F')] * 5),
    ('sql_injection', '100200', [f'[2026-10-02 10:00:00] SQLI ATTEMPT USER=test_OR_1=1 IP={IP}']),
    ('shellshock', '31168', [apache('/', status=200, user_agent='() { :; }; echo harmless')]),
    ('shellshock_404', '100490', [apache('/cgi-bin/test.sh', status=404, user_agent='() { :; }; echo harmless')]),
    ('web_brute_force', '100102', [
        f'[2026-10-02 10:00:00] FAILED LOGIN USER=test IP={IP}' for _ in range(5)
    ]),
    ('service_auth_failure', '100500', [
        structured_event(event_type='stis_auth_failed', srcip=IP,
                         dstuser='test', url='/v1/login')
    ]),
    ('service_brute_force', '100501', [
        structured_event(event_type='stis_auth_failed', srcip=IP,
                         dstuser='test', url='/v1/login')
        for _ in range(5)
    ]),
    ('application_sql_injection', '100510', [
        structured_event(event_type='stis_sqli_attempt', srcip=IP,
                         dstuser='test', url='/login')
    ]),
    ('website_content', '100300', [
        structured_event(event_type='web_content_threat', threat_type='gambling_spam',
                         file_path='/var/www/web1/guard-test.txt', matched_terms='situs_slot')
    ]),
    ('webshell_content', '100305', [
        structured_event(event_type='web_content_threat', threat_type='webshell_code',
                         file_path='/var/www/web1/guard-webshell-test.txt',
                         matched_terms='eval(base64_decode(')
    ]),
    ('website_integrity', '100301', [
        structured_event(event_type='web_integrity_change', change_type='modified',
                         file_path='/var/www/web1/guard-test.txt')
    ]),
]


def run_case(name, expected, lines, command=LOGTEST):
    # One logtest process per case keeps frequency counters isolated.
    result = subprocess.run(
        [command], input='\n'.join(lines) + '\n', text=True,
        capture_output=True, timeout=30, check=False,
    )
    output = result.stdout + result.stderr
    observed = re.findall(r"\bid:\s*'(\d+)'", output)
    actual = observed[-1] if observed else None
    if actual == expected:
        error = None
    elif actual == '86600':
        error = ('JSON decoded and matched built-in parent 86600, but no STIS child rule '
                 'matched. Check local_rules.xml on the Manager, then repeat wazuh-logtest.')
    elif observed:
        error = f'Expected rule {expected}, observed rule {actual}; inspect Phase 3.'
    else:
        error = output[-500:]
    return {
        'scenario': name, 'input_events': len(lines), 'expected_rule_id': expected,
        'observed_rule_id': actual, 'passed': actual == expected,
        'error': error,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logtest', default=LOGTEST, help='Path to wazuh-logtest on the Manager')
    args = parser.parse_args()
    results = []
    cases = list(CASES)
    reputation_list = Path('/var/ossec/etc/lists/stis-known-bad')
    if reputation_list.is_file() and '198.51.100.99:' in reputation_list.read_text():
        cases.append(('reviewed_ip_reputation', '100600',
                      [apache('/not-found', src_ip='198.51.100.99')]))
    for name, expected, lines in cases:
        try:
            results.append(run_case(name, expected, lines, args.logtest))
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({
                'scenario': name, 'input_events': len(lines), 'expected_rule_id': expected,
                'observed_rule_id': None, 'passed': False, 'error': str(exc),
            })
    report = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'method': 'wazuh-logtest; synthetic logs; no production alert or firewall change',
        'passed': sum(item['passed'] for item in results),
        'total': len(results), 'results': results,
    }
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] == report['total'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
