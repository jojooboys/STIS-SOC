"""Buat dataset sintetis deterministik; tidak membaca log atau database lokal."""

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'datasets' / 'dummy' / 'alerts.csv'

# Label disusun dari spesifikasi kebijakan, sebelum menjalankan evaluator.
# Semua IP/hostname/akun adalah contoh buatan; tidak ada identitas operasional.
CASES = [
    (100501, 10, 'brute_force', '192.0.2.11', 30, 'brute_force', 'block'),
    (100510, 12, 'sql_injection', '192.0.2.12', 30, 'sql_injection', 'block'),
    (100480, 8, 'ssrf', '192.0.2.13', 30, 'ssrf', 'below_threshold'),
    (100481, 10, 'ssrf', '192.0.2.14', 30, 'ssrf', 'block'),
    (100304, 10, 'web_defacement', '', 30, 'web_defacement', 'integrity_alert'),
    (100305, 14, 'webshell_content', '', 30, 'webshell_content', 'integrity_alert'),
    (100002, 10, 'brute_force', '192.0.2.254', 30, 'brute_force', 'whitelisted'),
    (100510, 12, 'sql_injection', '', 30, 'sql_injection', 'no_source_ip'),
    (100510, 12, 'sql_injection', '192.0.2.19', 3600, 'sql_injection', 'stale_alert'),
    (100610, 10, 'host_command', '', 30, 'host_command', 'review_only'),
    (999999, 12, 'unknown_demo', '192.0.2.21', 30, 'other', 'review_only'),
    (100468, 6, 'xss', '192.0.2.22', 30, 'xss', 'below_threshold'),
]
FIELDS = ['alert_id', 'rule_id', 'rule_level', 'rule_groups', 'agent_id',
          'agent_name', 'src_ip', 'dst_ip', 'age_seconds', 'rule_description',
          'full_log', 'expected_threat', 'expected_action']


def main():
    """Tulis 12 baris dengan struktur yang sama pada setiap pemanggilan."""
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    with TARGET.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator='\n')
        writer.writeheader()
        for index, (rule, level, group, ip, age, threat, action) in enumerate(CASES, 1):
            writer.writerow(dict(zip(FIELDS, [
                f'dummy-{index:03d}', rule, level, json.dumps([group]), 'DEMO-001',
                'server-demo.example', ip, '198.51.100.10', age,
                f'SYNTHETIC case {index:02d}; rule {rule}',
                f'SYNTHETIC event; user=USER_MASKED; host=HOST_MASKED; case={index:02d}',
                threat, action,
            ])))
    print(f'Dataset sintetis: {TARGET} ({len(CASES)} baris)')


if __name__ == '__main__':
    main()
