"""Luncurkan seluruh unittest dengan import backend dan website_guard tersedia.

Pemakaian dari root: python scripts/run_backend_tests.py
Setiap tes memakai SQLite memory/mock; skrip tidak membuka database operasional.
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    """Jalankan interpreter aktif; jangan bergantung pada aktivasi shell/OS."""
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join([str(ROOT), str(ROOT / 'backend')])
    env['FLASK_CONFIG'] = 'testing'
    return subprocess.call(
        [sys.executable, '-m', 'unittest', 'discover', '-s', 'backend/tests', '-v'],
        cwd=ROOT, env=env,
    )


if __name__ == '__main__':
    raise SystemExit(main())
