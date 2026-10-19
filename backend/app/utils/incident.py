"""Derive the affected endpoint and operator guidance from a Wazuh alert.

No attacker IP is inferred from FIM: a changed file identifies a target, not
the person or network source that changed it.
"""

import json
import re
from urllib.parse import urlsplit

from app.utils.threats import THREAT_GUIDANCE, can_auto_block, classify_alert


REQUEST_TARGET = re.compile(r'"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/', re.I)
SITE_LOG = re.compile(r'/var/log/stis-soc/(?:apache|apps)/([a-z0-9][a-z0-9_-]*)\.(?:access\.log|jsonl)\b', re.I)
SITE_ROOT = re.compile(r'^/var/www/([a-z0-9][a-z0-9_-]*)/', re.I)


def describe_incident(alert):
    """Gabungkan lokasi sasaran dan saran investigasi dari telemetry yang tersedia."""
    try:
        raw = json.loads(alert.raw_json or '{}')
    except (TypeError, ValueError):
        raw = {}
    data = raw.get('data') if isinstance(raw.get('data'), dict) else {}
    syscheck = raw.get('syscheck') if isinstance(raw.get('syscheck'), dict) else {}
    location = str(raw.get('location') or '')
    vt = data.get('virustotal') if isinstance(data.get('virustotal'), dict) else {}
    vt_source = vt.get('source') if isinstance(vt.get('source'), dict) else {}
    audit = data.get('audit') if isinstance(data.get('audit'), dict) else {}
    vulnerability = data.get('vulnerability') if isinstance(data.get('vulnerability'), dict) else {}
    package = vulnerability.get('package') if isinstance(vulnerability.get('package'), dict) else {}
    target = (data.get('file_path') or data.get('url') or syscheck.get('path')
              or vt_source.get('file') or audit.get('exe') or package.get('name')
              or data.get('file') or data.get('title') or '')
    if not target:
        match = REQUEST_TARGET.search(alert.full_log or '')
        target = match.group(1) if match else ''
    target = str(target)[:1000]

    from app.models import MonitoredAsset
    candidates = MonitoredAsset.query.filter_by(agent_id=alert.agent_id, enabled=True).all()
    asset = None
    for candidate in candidates:
        if candidate.root_path and target.startswith(candidate.root_path.rstrip('/') + '/'):
            asset = candidate
            break
        if (candidate.access_log_path and candidate.access_log_path in location or
                candidate.app_log_path and candidate.app_log_path in location):
            if target.startswith('/') and candidate.path_prefix != '/' and not target.startswith(candidate.path_prefix):
                continue
            asset = candidate
            break
    # Standard Agent-side paths identify a site even when no SOC asset row
    # exists. Structured events may also carry the actual domain/service name.
    site_match = SITE_LOG.search(location) or SITE_ROOT.match(target)
    site_name = site_match.group(1) if site_match else None
    event_name = data.get('asset_name') or data.get('service') or site_name
    event_domain = data.get('domain') or data.get('hostname')
    if not asset and not event_name and not event_domain and len(candidates) == 1:
        asset = candidates[0]
    if not event_domain and target.startswith(('http://', 'https://')):
        event_domain = urlsplit(target).hostname

    threat = classify_alert(alert)
    endpoint = target
    if target.startswith('http://') or target.startswith('https://'):
        parsed = urlsplit(target)
        endpoint = parsed.path or '/'
        if parsed.query:
            endpoint += '?' + parsed.query
    return {
        'asset_id': asset.id if asset else None,
        'asset_name': str(event_name)[:120] if event_name else (asset.name if asset else None),
        'domain': str(event_domain)[:255] if event_domain else (asset.domain if asset else None),
        'target': endpoint or None,
        'log_source': location or None,
        'mitigation_tip': THREAT_GUIDANCE[threat['code']],
        'auto_block_eligible': can_auto_block(alert),
    }
