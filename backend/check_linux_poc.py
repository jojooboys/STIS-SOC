"""Read-only evidence check for Linux PoC alerts imported into STIS SOC.

Run on UbuntuServer after a real Agent event, not as a replacement for
checking Wazuh Manager and the firewall independently.
"""

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


RULE_IDS = (100600, 100610, 100611, 510, 521, 87105)
GROUP_PATTERNS = ('%rootcheck%', '%virustotal%', '%vulnerability-detector%')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=Path('/root/backend/instance/soc.db'))
    parser.add_argument('--limit', type=int, default=10)
    parser.add_argument('--since', default=datetime.now(timezone.utc).date().isoformat(),
                        help='Tanggal UTC paling awal, YYYY-MM-DD; default hari ini')
    args = parser.parse_args()
    if not args.db.is_file():
        parser.error(f'Database SOC tidak ditemukan: {args.db}')
    if not 1 <= args.limit <= 100:
        parser.error('--limit harus antara 1 dan 100')
    try:
        datetime.strptime(args.since, '%Y-%m-%d')
    except ValueError:
        parser.error('--since harus berformat YYYY-MM-DD')

    # SQLite's read-only URI prevents this diagnostic from creating a database
    # when the operator points it at an incorrect path.
    with sqlite3.connect(args.db.resolve().as_uri() + '?mode=ro', uri=True) as conn:
        conn.row_factory = sqlite3.Row
        placeholders = ','.join('?' for _ in RULE_IDS)
        rows = conn.execute(
            f'SELECT rule_id, timestamp, rule_level, agent_name, src_ip, '
            f'action_taken, rule_description FROM alerts '
            f'WHERE (rule_id IN ({placeholders}) OR rule_groups LIKE ? '
            f'OR rule_groups LIKE ? OR rule_groups LIKE ?) AND timestamp >= ? '
            f'ORDER BY id DESC LIMIT ?',
            (*RULE_IDS, *GROUP_PATTERNS, args.since, args.limit),
        ).fetchall()
    print(json.dumps({
        'status': 'alerts_found' if rows else 'no_matching_alerts',
        'database': str(args.db),
        'since_utc': args.since,
        'rule_ids': RULE_IDS,
        'group_patterns': GROUP_PATTERNS,
        'alerts': [dict(row) for row in rows],
    }, indent=2))


if __name__ == '__main__':
    main()
