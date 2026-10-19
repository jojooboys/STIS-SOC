"""Evaluasi kebijakan respons aktual pada dataset sintetis, tanpa akses jaringan.

Jalankan dari root: python modelling/evaluate_response.py
Hasil adalah kecocokan label contoh, bukan efektivitas keamanan produksi.
"""

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
# Pakai fungsi aplikasi yang sama agar pemodelan tidak menduplikasi logika.
sys.path.insert(0, str(ROOT / 'backend'))
from app import create_app
from app.extensions import db
from app.services.response_engine import ResponseEngine
from app.utils.helpers import set_setting
from demo_dataset import DATASET, load_cases


def evaluate(dataset=DATASET):
    """Hitung kesesuaian kelas/aksi dan confusion matrix kelayakan block."""
    cases = load_cases(dataset)
    rows = []
    with patch('requests.sessions.Session.request', side_effect=RuntimeError('Evaluasi offline')):
        app = create_app('testing', start_scheduler=False)
        with app.app_context():
            set_setting('auto_response_enabled', 'true')
            set_setting('alert_threshold_level', '10')
            set_setting('auto_response_max_alert_age_seconds', '600')
            set_setting('whitelist_ips', '127.0.0.1,192.0.2.254')
            engine = ResponseEngine()
            try:
                for case in cases:
                    result = engine.evaluate_threat(case['alert'])
                    rows.append({
                        'alert_id': case['alert']['alert_id'],
                        'expected_threat': case['expected_threat'],
                        'actual_threat': result['threat_type'],
                        'expected_action': case['expected_action'],
                        'actual_action': result['action'],
                        'expected_block': case['expected_action'] == 'block',
                        'actual_block': result['block'],
                    })
            finally:
                db.session.remove()
                db.drop_all()
    matrix = {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0}
    for row in rows:
        key = ('tp' if row['actual_block'] else 'fn') if row['expected_block'] else (
            'fp' if row['actual_block'] else 'tn')
        matrix[key] += 1
    tp, fp, fn = matrix['tp'], matrix['fp'], matrix['fn']
    return {
        'dataset_type': 'synthetic_policy_examples', 'rows': len(rows),
        'policy': {'threshold': 10, 'max_age_seconds': 600, 'whitelist': '127.0.0.1,192.0.2.254'},
        'threat_matches': sum(r['expected_threat'] == r['actual_threat'] for r in rows),
        'action_matches': sum(r['expected_action'] == r['actual_action'] for r in rows),
        'block_confusion_matrix': matrix,
        'block_precision': tp / (tp + fp) if tp + fp else None,
        'block_recall': tp / (tp + fn) if tp + fn else None,
        'block_f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        'cases': rows,
    }


def main():
    """Cetak JSON; exit 1 bila ada label kebijakan yang tidak cocok."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, default=DATASET)
    parser.add_argument('--output', type=Path, help='Contoh: reports/evaluation.json')
    args = parser.parse_args()
    result = evaluate(args.dataset)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + '\n', encoding='utf-8')
    print(rendered)
    return 0 if result['action_matches'] == result['threat_matches'] == result['rows'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
