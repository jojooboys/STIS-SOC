"""Akses settings, catat audit, dan isi default tanpa menimpa nilai yang sudah ada."""

from datetime import datetime, timezone
from typing import Optional
from app.extensions import db
from app.models.setting import SocSetting
from app.models.audit_log import AuditLog

DEFAULT_WHITELIST = '127.0.0.1,10.10.10.0/24,192.168.1.0/24'

def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    """Retrieve a setting value from the database by its key."""
    setting = SocSetting.query.filter_by(key=key).first()
    if setting:
        return setting.value
    return default

def set_setting(key: str, value: str, updated_by: str = 'system') -> None:
    """Update or create a setting in the database."""
    setting = SocSetting.query.filter_by(key=key).first()
    if setting:
        setting.value = value
        setting.updated_by = updated_by
    else:
        setting = SocSetting(key=key, value=value, updated_by=updated_by)
        db.session.add(setting)
    db.session.commit()

def create_audit_log(action: str, details: str, performed_by: str = 'system',
                     ip_address: Optional[str] = None, result: str = 'success',
                     error_message: Optional[str] = None) -> None:
    """Convenience function to log an audit event to the database."""
    log = AuditLog(
        action=action,
        details=details,
        performed_by=performed_by,
        ip_address=ip_address,
        result=result,
        error_message=error_message
    )
    db.session.add(log)
    db.session.commit()

def init_default_settings() -> None:
    """Populate default SOC settings if they do not exist."""
    defaults = {
        # Wazuh configuration
        'wazuh_host': ('127.0.0.1', 'Wazuh server IP address'),
        'wazuh_api_port': ('55000', 'Wazuh Manager API port'),
        'wazuh_indexer_port': ('9200', 'Wazuh Indexer (OpenSearch) port'),
        'wazuh_api_user': ('wazuh', 'Wazuh Manager API administrator username'),
        'wazuh_api_password': ('', 'Wazuh Manager API password'),
        'wazuh_indexer_user': ('admin', 'Wazuh Indexer username'),
        'wazuh_indexer_password': ('', 'Wazuh Indexer password'),
        # pfSense configuration
        'pfsense_host': ('10.10.10.1', 'pfSense firewall address (LAN IP 10.10.10.1 or WAN IP)'),
        'pfsense_api_key': ('', 'pfSense REST API key'),
        'pfsense_alias_name': ('SOC_Blocklist', 'pfSense alias name for blocklist'),
        'pfsense_block_interface': ('wan', 'pfSense interface for block rules'),
        'pfsense_kill_states_on_block': ('true', 'Clear active pfSense states after blocking an IP'),
        # Auto-response configuration
        'auto_response_enabled': ('false', 'Enable/disable automatic IP blocking'),
        'alert_threshold_level': ('10', 'Minimum Wazuh rule level to trigger auto-block'),
        'polling_interval_seconds': ('60', 'Alert polling interval in seconds'),
        'auto_response_max_alert_age_seconds': ('600', 'Maximum alert age eligible for automatic blocking'),
        'whitelist_ips': (DEFAULT_WHITELIST, 'Comma-separated IPs/CIDRs that will never be blocked'),
    }

    for key, (value, description) in defaults.items():
        existing = SocSetting.query.filter_by(key=key).first()
        if not existing:
            setting = SocSetting(
                key=key,
                value=value,
                description=description,
                updated_by='system'
            )
            db.session.add(setting)

    db.session.commit()

def get_utc_now() -> datetime:
    """Return a timezone-aware datetime object for current UTC time."""
    return datetime.now(timezone.utc)
