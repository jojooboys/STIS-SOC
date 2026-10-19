"""Store Wazuh alerts, decide response eligibility, and record pfSense actions."""

import logging
import re
from datetime import datetime, timezone
from app.services.wazuh_service import WazuhService
from app.services.pfsense_service import PfSenseService

logger = logging.getLogger(__name__)

class ResponseEngine:
    """Automated incident response engine. Evaluates alerts and executes blocking actions."""

    def __init__(self, app=None):
        self.app = app
        self._wazuh_service = None
        self._pfsense_service = None

    @property
    def wazuh_service(self):
        if not self._wazuh_service:
            self._wazuh_service = WazuhService()
        return self._wazuh_service

    @property
    def pfsense_service(self):
        if not self._pfsense_service:
            self._pfsense_service = PfSenseService()
        return self._pfsense_service

    def process_alerts(self, alerts: list[dict]) -> dict:
        from app.extensions import db
        from app.models import Alert
        from app.utils.threats import response_priority

        summary = {"total": len(alerts), "saved": 0, "blocked": 0, "skipped": 0, "block_failed": 0, "actions": {}}

        # One request can produce both a specific attack alert and a generic
        # Apache 4xx alert. Process the strongest alert first so the block
        # history records the real trigger (for example SQL Injection L12).
        prioritized_alerts = sorted(alerts, key=response_priority, reverse=True)

        for alert_data in prioritized_alerts:
            # Check if alert already exists
            existing_alert = Alert.query.filter_by(alert_id=alert_data['alert_id']).first()
            if existing_alert:
                summary["skipped"] += 1
                continue

            # Normalize Wazuh timestamp variants before saving and evaluating.
            raw_timestamp = alert_data.get('timestamp')
            ts = self._parse_alert_timestamp(raw_timestamp)
            normalized_timestamp = ts.isoformat() if ts else str(raw_timestamp or '')
            if ts is None:
                logger.warning(
                    "Alert %s has an unsupported timestamp %r",
                    alert_data.get('alert_id'), raw_timestamp
                )

            # Save alert to DB
            new_alert = Alert(
                alert_id=alert_data['alert_id'],
                timestamp=normalized_timestamp,
                rule_id=alert_data['rule_id'],
                rule_level=alert_data['rule_level'],
                rule_description=alert_data['rule_description'],
                rule_groups=alert_data['rule_groups'],
                agent_id=alert_data['agent_id'],
                agent_name=alert_data['agent_name'],
                src_ip=alert_data['src_ip'],
                dst_ip=alert_data['dst_ip'],
                src_port=alert_data['src_port'],
                dst_port=alert_data['dst_port'],
                full_log=alert_data['full_log'],
                raw_json=alert_data['raw_json']
            )
            db.session.add(new_alert)

            # Flush to get the ID
            try:
                db.session.flush()
                summary["saved"] += 1
            except Exception as e:
                logger.error(f"Error saving alert {alert_data['alert_id']}: {e}")
                db.session.rollback()
                continue

            # Evaluate threat
            evaluation_data = dict(alert_data)
            evaluation_data['timestamp'] = normalized_timestamp
            eval_result = self.evaluate_threat(evaluation_data)
            action = eval_result.get('action', 'unknown')
            if eval_result.get("block", False):
                block_result = self.execute_block(
                    ip_address=alert_data['src_ip'],
                    alert_db_id=new_alert.id,
                    reason=eval_result.get("reason", "Auto-response block"),
                    performed_by='auto-response'
                )
                if block_result.get('status') == 'success':
                    summary["blocked"] += 1
                    action = block_result.get('action', 'blocked')
                else:
                    summary['block_failed'] += 1
                    action = 'block_failed'
            new_alert.is_processed = True
            new_alert.action_taken = action
            summary['actions'][action] = summary['actions'].get(action, 0) + 1

        db.session.commit()
        return summary

    def reprocess_recent_alerts(self) -> dict:
        """Re-evaluate recent alerts deferred by settings or a transient block failure."""
        from app.extensions import db
        from app.models import Alert
        from app.utils.helpers import get_setting

        max_age = max(60, int(get_setting('auto_response_max_alert_age_seconds', '600')))
        deferred_actions = (
            'disabled', 'below_threshold', 'whitelisted', 'stale_alert',
            'invalid_timestamp', 'block_failed'
        )
        candidates = (
            Alert.query
            .filter(Alert.action_taken.in_(deferred_actions))
            .order_by(Alert.id.desc())
            .limit(100)
            .all()
        )
        summary = {"checked": len(candidates), "blocked": 0, "block_failed": 0, "actions": {}}

        for alert in candidates:
            alert_data = self._model_to_alert_data(alert)
            if self._alert_age_seconds(alert_data.get('timestamp')) > max_age:
                continue
            result = self.evaluate_threat(alert_data)
            action = result.get('action', 'unknown')
            if result.get('block'):
                block_result = self.execute_block(
                    ip_address=alert.src_ip,
                    alert_db_id=alert.id,
                    reason=result.get('reason', 'Auto-response block'),
                    performed_by='auto-response',
                )
                if block_result.get('status') == 'success':
                    action = block_result.get('action', 'blocked')
                    summary['blocked'] += 1
                else:
                    action = 'block_failed'
                    summary['block_failed'] += 1
            alert.is_processed = True
            alert.action_taken = action
            summary['actions'][action] = summary['actions'].get(action, 0) + 1

        db.session.commit()
        return summary

    @staticmethod
    def _model_to_alert_data(alert) -> dict:
        return {
            'alert_id': alert.alert_id,
            'timestamp': alert.timestamp,
            'rule_id': alert.rule_id,
            'rule_level': alert.rule_level,
            'rule_description': alert.rule_description,
            'rule_groups': alert.rule_groups,
            'agent_id': alert.agent_id,
            'agent_name': alert.agent_name,
            'src_ip': alert.src_ip,
            'dst_ip': alert.dst_ip,
            'src_port': alert.src_port,
            'dst_port': alert.dst_port,
            'full_log': alert.full_log,
            'raw_json': alert.raw_json,
        }

    @staticmethod
    def _parse_alert_timestamp(timestamp):
        if isinstance(timestamp, datetime):
            parsed = timestamp
        elif isinstance(timestamp, (int, float)):
            value = float(timestamp)
            if value > 10_000_000_000:
                value /= 1000
            try:
                parsed = datetime.fromtimestamp(value, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                return None
        else:
            text = str(timestamp or '').strip()
            if not text:
                return None
            # Accept common Wazuh/OpenSearch forms: Z, +0700, +07:00,
            # comma fractional seconds, and a space in place of T.
            text = text.replace(',', '.')
            if text.endswith(('Z', 'z')):
                text = text[:-1] + '+00:00'
            text = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', text)
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError:
                parsed = None
                for pattern in (
                    '%Y-%m-%dT%H:%M:%S.%f%z',
                    '%Y-%m-%dT%H:%M:%S%z',
                    '%Y-%m-%d %H:%M:%S.%f%z',
                    '%Y-%m-%d %H:%M:%S%z',
                    '%Y-%m-%dT%H:%M:%S.%f',
                    '%Y-%m-%dT%H:%M:%S',
                    '%Y-%m-%d %H:%M:%S',
                ):
                    try:
                        parsed = datetime.strptime(text, pattern)
                        break
                    except ValueError:
                        continue
                if parsed is None:
                    return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    @classmethod
    def _alert_age_seconds(cls, timestamp) -> float:
        alert_time = cls._parse_alert_timestamp(timestamp)
        if alert_time is None:
            return float('inf')
        try:
            return (datetime.now(timezone.utc) - alert_time).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return float('inf')

    def evaluate_threat(self, alert_data: dict) -> dict:
        from app.utils.helpers import get_setting, DEFAULT_WHITELIST
        from app.utils.threats import can_auto_block, classify_alert
        from app.utils.validators import is_valid_ipv4, is_ip_in_whitelist
        from app.models import BlockedIP

        threat = classify_alert(alert_data)
        context = {
            'threat_type': threat['code'],
            'threat_label': threat['label'],
        }
        auto_response_enabled = str(get_setting('auto_response_enabled', 'false')).lower() == 'true'
        threshold = int(get_setting('alert_threshold_level', '10'))
        whitelist_ips_str = get_setting('whitelist_ips', DEFAULT_WHITELIST)

        if not auto_response_enabled:
            return {**context, "action": "disabled", "block": False}

        rule_level = int(alert_data.get('rule_level') or 0)
        if rule_level < threshold:
            return {**context, "action": "below_threshold", "block": False}

        if threat['code'] in {'web_defacement', 'webshell_content'}:
            # A source address attached to a file event is not proof that it
            # changed the file. Investigation must precede any IP response.
            return {**context, "action": "integrity_alert", "block": False}
        if not can_auto_block(alert_data):
            return {**context, "action": "review_only", "block": False}

        src_ip = alert_data.get('src_ip')
        if not src_ip or not is_valid_ipv4(src_ip):
            return {**context, "action": "no_source_ip", "block": False}

        if is_ip_in_whitelist(src_ip, whitelist_ips_str):
            return {**context, "action": "whitelisted", "block": False}

        # Importing old alerts must not trigger a surprise firewall change.
        max_age = max(60, int(get_setting('auto_response_max_alert_age_seconds', '600')))
        age_seconds = self._alert_age_seconds(alert_data.get('timestamp'))
        if age_seconds == float('inf'):
            return {**context, "action": "invalid_timestamp", "block": False}
        if age_seconds > max_age:
            return {**context, "action": "stale_alert", "block": False}

        # Check if already blocked in DB
        already_blocked = BlockedIP.query.filter_by(ip_address=src_ip, status='blocked').first()
        if already_blocked:
            return {
                **context,
                "action": "reinforce_block",
                "block": True,
                "reason": (
                    f"Reinforced block for {threat['label']}: "
                    f"{alert_data.get('rule_description')} "
                    f"(Rule {alert_data.get('rule_id')}, Level {rule_level})"
                ),
            }

        return {
            **context,
            "action": "block",
            "block": True,
            "reason": (
                f"Auto-blocked {threat['label']}: {alert_data.get('rule_description')} "
                f"(Rule {alert_data.get('rule_id')}, Level {rule_level})"
            )
        }

    def execute_block(self, ip_address: str, alert_db_id: int, reason: str, performed_by: str = 'auto-response') -> dict:
        from app.extensions import db
        from app.models import Alert, BlockedIP
        from app.utils.helpers import create_audit_log
        from app.utils.threats import response_priority

        try:
            existing_block = BlockedIP.query.filter_by(
                ip_address=ip_address,
                status='blocked',
            ).first()
            res = self.pfsense_service.block_ip(ip_address, reason)

            if res.get('status') == 'success':
                cleanup = res.get('state_cleanup') or {}
                cleanup_warning = ''
                if cleanup.get('status') == 'error':
                    cleanup_warning = f" Active-state cleanup warning: {cleanup.get('message', 'unknown error')}."
                if existing_block:
                    metadata_upgraded = False
                    trigger_alert = db.session.get(Alert, alert_db_id) if alert_db_id else None
                    previous_alert = (
                        db.session.get(Alert, existing_block.alert_id)
                        if existing_block.alert_id else None
                    )
                    if (
                        existing_block.source == 'auto'
                        and trigger_alert is not None
                        and response_priority(trigger_alert) > response_priority(previous_alert)
                    ):
                        # Never let a later generic 4xx alert replace a more
                        # specific/higher-level trigger. A specific alert that
                        # arrives in a later polling cycle may upgrade it.
                        existing_block.reason = reason
                        existing_block.alert_id = trigger_alert.id
                        metadata_upgraded = True

                    result_action = 'block_reinforced'
                    audit_action = 'block_ip_reinforced'
                    audit_details = (
                        f"IP {ip_address} block verified/reinforced on pfSense. "
                        f"Trigger: {reason}."
                        f"{' Block history trigger upgraded.' if metadata_upgraded else ''}"
                        f"{cleanup_warning}"
                    )
                else:
                    blocked_ip = BlockedIP(
                        ip_address=ip_address,
                        reason=reason,
                        source='auto' if performed_by == 'auto-response' else 'manual',
                        alert_id=alert_db_id,
                        pfsense_rule_id=res.get('rule_id', ''),
                        status='blocked',
                        blocked_by=performed_by
                    )
                    db.session.add(blocked_ip)
                    db.session.flush()
                    result_action = 'blocked'
                    audit_action = 'block_ip'
                    audit_details = (
                        f"IP {ip_address} blocked successfully. Reason: "
                        f"{reason}.{cleanup_warning}"
                    )

                create_audit_log(
                    action=audit_action,
                    details=audit_details,
                    performed_by=performed_by,
                    ip_address=ip_address,
                    result='success'
                )
                return {
                    "status": "success",
                    "message": f"Successfully blocked {ip_address}",
                    "action": result_action,
                    "state_cleanup": cleanup or None,
                }
            else:
                error_message = res.get('message', 'Unknown pfSense error')
                logger.error(f"Failed to block IP {ip_address} on pfSense: {error_message}")
                create_audit_log(
                    action='block_ip',
                    details=f"Failed to block {ip_address} on pfSense: {error_message}",
                    performed_by=performed_by,
                    ip_address=ip_address,
                    result='failure',
                    error_message=error_message
                )
                return {"status": "error", "message": f"pfSense rejected block request: {error_message}"}
        except Exception as e:
            logger.error(f"Exception during block execution for IP {ip_address}: {e}")
            create_audit_log(
                action='block_ip',
                details=f"Exception during block of {ip_address}: {str(e)}",
                performed_by=performed_by,
                ip_address=ip_address,
                result='failure',
                error_message=str(e)
            )
            return {"status": "error", "message": f"Exception during block: {str(e)}"}

    def manual_block(self, ip_address: str, reason: str, performed_by: str) -> dict:
        from app.extensions import db
        from app.models import BlockedIP
        from app.utils.validators import is_valid_ipv4
        from app.utils.helpers import create_audit_log

        if not is_valid_ipv4(ip_address):
            return {"status": "error", "message": "Invalid IPv4 address"}

        already_blocked = BlockedIP.query.filter_by(ip_address=ip_address, status='blocked').first()
        if already_blocked:
            return {"status": "error", "message": "IP is already blocked"}

        result = self.execute_block(ip_address, None, reason, str(performed_by))
        db.session.commit()

        return result

    def manual_reblock(self, blocked_ip, performed_by: str) -> dict:
        """Reapply an unblocked record without creating a duplicate history row."""
        from app.utils.helpers import create_audit_log
        from app.extensions import db

        try:
            result = self.pfsense_service.block_ip(blocked_ip.ip_address, blocked_ip.reason or 'Blocked again from history')
            if result.get('status') == 'success':
                blocked_ip.status = 'blocked'
                blocked_ip.blocked_at = datetime.now(timezone.utc)
                blocked_ip.blocked_by = performed_by
                blocked_ip.unblocked_at = None
                blocked_ip.unblocked_by = None
                blocked_ip.source = 'manual'
                create_audit_log(
                    action='block_ip',
                    details=f"IP {blocked_ip.ip_address} blocked again from history",
                    performed_by=performed_by,
                    ip_address=blocked_ip.ip_address,
                )
                db.session.commit()
                return {"status": "success", "message": f"Blocked {blocked_ip.ip_address} again"}

            message = result.get('message', 'Unknown pfSense error')
            create_audit_log(
                action='block_ip',
                details=f"Failed to block {blocked_ip.ip_address} again: {message}",
                performed_by=performed_by,
                ip_address=blocked_ip.ip_address,
                result='failure',
                error_message=message,
            )
            return {"status": "error", "message": message}
        except Exception as error:
            logger.exception("Failed to block %s again", blocked_ip.ip_address)
            create_audit_log(
                action='block_ip',
                details=f"Failed to block {blocked_ip.ip_address} again: {error}",
                performed_by=performed_by,
                ip_address=blocked_ip.ip_address,
                result='failure',
                error_message=str(error),
            )
            return {"status": "error", "message": str(error)}

    def manual_unblock(self, blocked_ip_id: int, performed_by: str) -> dict:
        from app.extensions import db
        from app.models import BlockedIP
        from app.utils.helpers import create_audit_log

        blocked_ip = db.session.get(BlockedIP, blocked_ip_id)
        if not blocked_ip or blocked_ip.status != 'blocked':
            return {"status": "error", "message": "Block record not found or not currently blocked"}

        try:
            res = self.pfsense_service.unblock_ip(blocked_ip.ip_address)

            if res.get('status') == 'success':
                blocked_ip.status = 'unblocked'
                blocked_ip.unblocked_at = datetime.now(timezone.utc)
                blocked_ip.unblocked_by = str(performed_by)

                create_audit_log(
                    action='unblock_ip',
                    details=f"IP {blocked_ip.ip_address} unblocked successfully",
                    performed_by=str(performed_by),
                    ip_address=blocked_ip.ip_address,
                    result='success'
                )
                db.session.commit()
                return {"status": "success", "message": f"Successfully unblocked {blocked_ip.ip_address}"}
            else:
                create_audit_log(
                    action='unblock_ip',
                    details=f"Failed to unblock {blocked_ip.ip_address} on pfSense: {res.get('message')}",
                    performed_by=str(performed_by),
                    ip_address=blocked_ip.ip_address,
                    result='failure',
                    error_message=res.get('message', '')
                )
                return {"status": "error", "message": f"Failed to unblock on pfSense: {res.get('message')}"}
        except Exception as e:
            logger.error(f"Exception during manual unblock: {e}")
            create_audit_log(
                action='unblock_ip',
                details=f"Exception during unblock of {blocked_ip.ip_address}: {str(e)}",
                performed_by=str(performed_by),
                ip_address=blocked_ip.ip_address,
                result='failure',
                error_message=str(e)
            )
            return {"status": "error", "message": f"Exception during unblock: {str(e)}"}
