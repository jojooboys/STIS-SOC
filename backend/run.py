"""Jalankan API lab, atau preview sintetis terisolasi dengan --demo."""

import os
import sys
import logging
from app import create_app

logging.basicConfig(
    level=getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO),
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
)

# Instantiate the application
if __name__ == '__main__' and '--demo' in sys.argv:
    from seed_demo_data import create_demo_app
    # Mode demo tidak membuat scheduler dan tidak membaca database soc.db.
    app = create_demo_app()
else:
    app = create_app(os.environ.get('FLASK_CONFIG', 'development'))

if __name__ == '__main__':
    # Run the application
    # Host '0.0.0.0' allows external connections
    # A single process owns the background scheduler. Source updates are applied
    # by stop_soc.sh/start_soc.sh rather than Werkzeug's development reloader.
    app.run(host='0.0.0.0', port=5000, use_reloader=False, use_debugger=False)
