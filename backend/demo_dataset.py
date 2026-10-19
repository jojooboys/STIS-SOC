"""Baca CSV publik menjadi alert terstandardisasi tanpa mengakses integrasi."""

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATASET = Path(__file__).resolve().parents[1] / 'datasets' / 'dummy' / 'alerts.csv'


def load_cases(path=DATASET):
    """Gunakan usia relatif agar kasus lama tetap dapat direplikasi kapan pun."""
    now = datetime.now(timezone.utc)
    with Path(path).open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError('Dataset tidak boleh kosong')
    cases = []
    for row in rows:
        groups = json.loads(row['rule_groups'])
        age = int(row['age_seconds'])
        if not isinstance(groups, list) or age < 0:
            raise ValueError(f"Kelompok/usia alert tidak valid: {row['alert_id']}")
        alert = {
            'alert_id': row['alert_id'],
            'timestamp': (now - timedelta(seconds=age)).isoformat(),
            'rule_id': int(row['rule_id']), 'rule_level': int(row['rule_level']),
            'rule_description': row['rule_description'], 'rule_groups': json.dumps(groups),
            'agent_id': row['agent_id'], 'agent_name': row['agent_name'],
            'src_ip': row['src_ip'] or None, 'dst_ip': row['dst_ip'] or None,
            'src_port': None, 'dst_port': None, 'full_log': row['full_log'],
            'raw_json': json.dumps({'synthetic': True, 'dataset_row': row}),
        }
        cases.append({'alert': alert, 'expected_threat': row['expected_threat'],
                      'expected_action': row['expected_action']})
    if len({case['alert']['alert_id'] for case in cases}) != len(cases):
        raise ValueError('alert_id pada dataset harus unik')
    return cases
