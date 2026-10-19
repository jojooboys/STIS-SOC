"""Poll Wazuh and persist scheduler status for the SOC dashboard."""

import logging
import json
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()


def _save_scheduler_state(status: str, summary: dict = None, error: str = None):
    """Persist scheduler health so the UI and diagnostics can explain failures."""
    from app.extensions import db
    from app.models import SocSetting

    values = {
        'auto_response_last_run': datetime.now(timezone.utc).isoformat(),
        'auto_response_last_status': status,
        'auto_response_last_summary': json.dumps(summary or {}, sort_keys=True),
        'auto_response_last_error': error or '',
    }
    for key, value in values.items():
        setting = SocSetting.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            db.session.add(SocSetting(key=key, value=value, updated_by='scheduler'))
    db.session.commit()

def fetch_and_process_alerts(app):
    """Ambil alert baru, evaluasi ulang respons tertunda, lalu simpan checkpoint dan status."""
    with app.app_context():
        try:
            from app.services.alert_purge_service import active_purge
            if active_purge():
                logger.info('Wazuh polling paused while alert deletion is running')
                return
            from app.utils.helpers import get_setting
            from app.models import SocSetting
            from app.extensions import db
            from app.services.wazuh_service import WazuhService
            from app.services.response_engine import ResponseEngine

            last_fetch_setting = SocSetting.query.filter_by(key='last_fetch_timestamp').first()
            since = last_fetch_setting.value if last_fetch_setting and last_fetch_setting.value else None

            engine = ResponseEngine(app=app)
            deferred_summary = engine.reprocess_recent_alerts()

            wazuh = WazuhService()
            alerts = wazuh.get_alerts(since=since)
            summary = {"total": 0, "saved": 0, "blocked": 0, "skipped": 0, "block_failed": 0, "actions": {}}
            if alerts:
                summary = engine.process_alerts(alerts)
                logger.info(f"Processed {len(alerts)} alerts. Summary: {summary}")

                # Keep a canonical checkpoint. Comparing raw timestamp strings
                # can select the wrong value when Wazuh varies its UTC-offset format.
                parsed_times = [
                    engine._parse_alert_timestamp(alert.get('timestamp'))
                    for alert in alerts
                ]
                valid_times = [timestamp for timestamp in parsed_times if timestamp]
                if valid_times:
                    latest_alert_time = max(valid_times).isoformat()
                    if not last_fetch_setting:
                        last_fetch_setting = SocSetting(
                            key='last_fetch_timestamp', value=latest_alert_time
                        )
                        db.session.add(last_fetch_setting)
                    else:
                        last_fetch_setting.value = latest_alert_time
                else:
                    logger.warning(
                        "No valid Wazuh timestamp was available; fetch checkpoint was not advanced."
                    )

                db.session.commit()
            combined = {"new_alerts": summary, "deferred_alerts": deferred_summary}
            _save_scheduler_state('success', combined)
            logger.info("Auto-response cycle completed: %s", combined)
        except Exception as e:
            logger.exception("Error in fetch_and_process_alerts")
            from app.extensions import db
            db.session.rollback()
            try:
                _save_scheduler_state('failure', error=str(e))
            except Exception:
                logger.exception("Could not persist scheduler failure state")

def reconcile_alert_purge(app):
    """Periksa tugas penghapusan tanpa menghentikan scheduler ketika Indexer gagal."""
    with app.app_context():
        try:
            from app.services.alert_purge_service import reconcile_running
            reconcile_running()
        except Exception:
            logger.exception('Could not reconcile Wazuh Indexer alert deletion')
            from app.extensions import db
            db.session.rollback()

def init_scheduler(app):
    """Initialize APScheduler with SOC background jobs."""
    try:
        from app.utils.helpers import get_setting

        with app.app_context():
            interval_seconds = int(get_setting('polling_interval_seconds', '60'))

        scheduler.add_job(
            func=fetch_and_process_alerts,
            args=[app],
            trigger=IntervalTrigger(seconds=interval_seconds),
            id='poll_wazuh_alerts',
            name='Poll Wazuh for new alerts',
            replace_existing=True,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=2),
            coalesce=True,
            max_instances=1,
            misfire_grace_time=max(30, interval_seconds),
        )

        # Old SOC-only cleanup was removed: it left Indexer documents untouched
        # and could invalidate a future preview count.
        old_cleanup = scheduler.get_job('cleanup_old_data')
        if old_cleanup:
            old_cleanup.remove()
        scheduler.add_job(
            func=reconcile_alert_purge,
            args=[app],
            trigger=IntervalTrigger(seconds=15),
            id='reconcile_alert_purge',
            name='Finish confirmed Indexer alert deletion',
            replace_existing=True,
            coalesce=True,
            max_instances=1,
        )

        if not scheduler.running:
            scheduler.start()
            logger.info("Scheduler started successfully; Wazuh polling interval is %s seconds.", interval_seconds)

    except Exception as e:
        logger.error(f"Failed to initialize scheduler: {e}")

def stop_scheduler():
    """Hentikan job latar belakang sebelum proses aplikasi berakhir."""
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped.")


def reschedule_polling_job(interval_seconds: int):
    """Apply a changed polling interval without requiring a backend restart."""
    interval_seconds = max(10, int(interval_seconds))
    job = scheduler.get_job('poll_wazuh_alerts')
    if job:
        scheduler.reschedule_job(
            'poll_wazuh_alerts',
            trigger=IntervalTrigger(seconds=interval_seconds),
        )
        logger.info("Wazuh polling interval changed to %s seconds.", interval_seconds)
