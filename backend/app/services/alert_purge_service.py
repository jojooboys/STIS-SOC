"""Delete a confirmed time window from the Wazuh Indexer and SOC cache.

The Indexer is authoritative. SOC rows are removed only after its asynchronous
delete task succeeds; firewall blocks and audit history are retained.
"""

import calendar
import hashlib
import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from sqlalchemy import func

from app.extensions import db
from app.models import Alert, AlertPurge, AuditLog, BlockedIP, User
from app.services.response_engine import ResponseEngine
from app.services.wazuh_service import WazuhService
from app.utils.helpers import create_audit_log


WIB = timezone(timedelta(hours=7), 'WIB')
PHRASE = 'HAPUS ALERT WAZUH'
INDEX = 'wazuh-alerts-*'
_reconcile_lock = threading.Lock()
_start_lock = threading.Lock()
logger = logging.getLogger(__name__)


def _utc(value):
    """Format waktu sebagai UTC milidetik untuk query Indexer."""
    return value.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _parse(value):
    """Baca timestamp ISO yang disimpan oleh alur penghapusan."""
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _naive_now():
    """Buat waktu UTC tanpa tzinfo sesuai kolom DateTime SQLite."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _subtract_months(value, months):
    """Geser bulan dengan hari yang dijepit ke akhir bulan tujuan."""
    year, month = divmod(value.year * 12 + value.month - 1 - months, 12)
    month += 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def window(period, *, now=None):
    """Return an exclusive UTC cutoff for alerts older than the selection."""
    now = now or datetime.now(timezone.utc)
    local = now.astimezone(WIB)
    if period == 'week':
        cutoff = local - timedelta(days=7)
    elif period == 'month':
        cutoff = _subtract_months(local, 1)
    elif period == 'six_months':
        cutoff = _subtract_months(local, 6)
    elif period == 'year':
        cutoff = _subtract_months(local, 12)
    elif period == 'all':
        return None, _utc(now)
    else:
        raise ValueError('Pilihan rentang waktu tidak valid')
    return None, _utc(cutoff)


def _query(purge):
    """Susun query batas waktu eksklusif dari pratinjau yang sudah dibekukan."""
    bounds = {'lt': purge.to_utc}
    if purge.from_utc:
        bounds['gte'] = purge.from_utc
    return {'query': {'range': {'timestamp': bounds}}}


def _indexer(method, path, *, body=None, timeout=30):
    """Kirim permintaan Indexer dan lempar error HTTP sebelum memakai respons."""
    wazuh = WazuhService()
    cfg = wazuh._get_config()
    url = f"https://{cfg['wazuh_host']}:{cfg['wazuh_indexer_port']}{path}"
    response = wazuh.session.request(
        method, url,
        auth=(cfg['wazuh_indexer_user'], cfg['wazuh_indexer_password']),
        json=body, timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def _count_indexer(purge):
    """Hitung dokumen Indexer yang termasuk rentang penghapusan."""
    result = _indexer(
        'POST', f'/{INDEX}/_count?ignore_unavailable=true&allow_no_indices=true',
        body=_query(purge),
    )
    return int(result['count'])


def _local_ids(purge):
    """Iterasikan ID lokal per batch setelah menormalisasi format timestamp lama."""
    end = _parse(purge.to_utc)
    # Old SOC rows contain more than one ISO offset format. Compare actual
    # instants instead of relying on lexicographic SQL string comparisons.
    last_id = 0
    while True:
        rows = (db.session.query(Alert.id, Alert.timestamp)
                .filter(Alert.id > last_id).order_by(Alert.id).limit(1000).all())
        if not rows:
            return
        for alert_id, timestamp in rows:
            parsed = ResponseEngine._parse_alert_timestamp(timestamp)
            if parsed is not None and parsed.astimezone(timezone.utc) < end:
                yield alert_id
        last_id = rows[-1][0]


def _count_local(purge):
    """Hitung alert cache lokal dalam rentang yang sama dengan pratinjau."""
    return sum(1 for _ in _local_ids(purge))


def active_purge():
    """Cari tugas yang masih memulai atau menjalankan penghapusan."""
    return AlertPurge.query.filter(AlertPurge.status.in_(('starting', 'running'))).first()


def _too_many_failures(user_id):
    """Batasi percobaan verifikasi berdasarkan total kegagalan 15 menit terakhir."""
    attempts = db.session.query(func.coalesce(func.sum(AlertPurge.attempts), 0)).filter(
        AlertPurge.user_id == user_id,
        AlertPurge.created_at >= _naive_now() - timedelta(minutes=15),
    ).scalar()
    return attempts >= 3


def preview(user, period):
    """Bekukan rentang/jumlah dan buat token sekali pakai untuk konfirmasi admin."""
    if _too_many_failures(user.id):
        raise RuntimeError('Terlalu banyak kegagalan verifikasi; coba lagi dalam 15 menit')
    if active_purge():
        raise RuntimeError('Penghapusan lain masih berjalan')
    lower, upper = window(period)
    token = secrets.token_urlsafe(32)
    purge = AlertPurge(
        user_id=user.id,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        period=period, scope='older', from_utc=lower, to_utc=upper,
        expected_indexer=0, expected_soc=0,
        expires_at=_naive_now() + timedelta(minutes=5),
    )
    purge.expected_indexer = _count_indexer(purge)
    purge.expected_soc = _count_local(purge)
    # Only the latest preview for this account can be confirmed.
    AlertPurge.query.filter_by(user_id=user.id, status='pending').update({'status': 'expired'})
    db.session.add(purge)
    db.session.commit()
    return {'token': token, **describe(purge), 'confirmation_phrase': PHRASE}


def describe(purge):
    """Sajikan status tugas tanpa mengungkap token verifikasi."""
    return {
        'id': purge.id,
        'period': purge.period,
        'scope': purge.scope,
        'from_utc': purge.from_utc,
        'to_utc': purge.to_utc,
        'indexer_count': purge.expected_indexer,
        'soc_count': purge.expected_soc,
        'indexer_deleted': purge.indexer_deleted,
        'soc_deleted': purge.soc_deleted,
        'status': purge.status,
        'error': purge.error,
    }


def confirm(user, token, password, phrase):
    # The development server is threaded; serialize the check/start transition
    # so two tabs cannot launch overlapping destructive Indexer tasks.
    """Serialisasikan konfirmasi agar dua permintaan tidak memulai tugas bersamaan."""
    with _start_lock:
        return _confirm_locked(user, token, password, phrase)


def _confirm_locked(user, token, password, phrase):
    """Verifikasi akun, password, frasa, token, dan jumlah sebelum meminta penghapusan."""
    if _too_many_failures(user.id):
        raise RuntimeError('Terlalu banyak kegagalan verifikasi; coba lagi dalam 15 menit')
    token_hash = hashlib.sha256(str(token).encode()).hexdigest()
    purge = AlertPurge.query.filter_by(token_hash=token_hash, user_id=user.id).first()
    if not purge or purge.status != 'pending' or purge.expires_at < _naive_now():
        raise ValueError('Pratinjau kedaluwarsa; buat pratinjau baru')
    if not user.check_password(password) or phrase != PHRASE:
        purge.attempts += 1
        if purge.attempts >= 3:
            purge.status = 'expired'
        db.session.commit()
        raise PermissionError('Password atau frasa konfirmasi salah')
    if active_purge():
        raise RuntimeError('Penghapusan lain masih berjalan')
    if _count_indexer(purge) != purge.expected_indexer or _count_local(purge) != purge.expected_soc:
        purge.status = 'expired'
        db.session.commit()
        raise ValueError('Jumlah alert berubah; buat pratinjau baru sebelum menghapus')
    purge.status = 'starting'
    purge.started_at = _naive_now()
    db.session.commit()
    try:
        result = _indexer(
            'POST',
            f'/{INDEX}/_delete_by_query?conflicts=proceed&wait_for_completion=false&refresh=true&ignore_unavailable=true&allow_no_indices=true',
            body=_query(purge), timeout=30,
        )
        task_id = result.get('task')
        if not task_id:
            raise RuntimeError('Indexer tidak mengembalikan ID tugas; periksa Indexer sebelum mengulang')
        purge.task_id = task_id
        purge.status = 'running'
        db.session.commit()
    except Exception as error:
        db.session.rollback()
        purge.status = 'failed'
        purge.error = str(error)[:500]
        purge.finished_at = _naive_now()
        db.session.commit()
        try:
            create_audit_log(
                action='purge_alerts', details=f'Gagal memulai penghapusan {purge.id}',
                performed_by=user.username, result='failure', error_message=purge.error,
            )
        except Exception:
            db.session.rollback()
            logger.exception('Could not write failure audit entry for alert purge %s', purge.id)
        raise
    try:
        create_audit_log(
            action='purge_alerts',
            details=f'Mulai hapus alert lebih tua dari {purge.period}, sebelum {purge.to_utc}; Indexer={purge.expected_indexer}, SOC={purge.expected_soc}',
            performed_by=user.username,
        )
    except Exception:
        db.session.rollback()
        logger.exception('Could not write audit entry for started alert purge %s', purge.id)
    return describe(purge)


def _finish_local(purge):
    """Hapus cache setelah Indexer berhasil; pertahankan riwayat blokir dan audit."""
    deleted = 0
    batch = []
    for alert_id in _local_ids(purge):
        batch.append(alert_id)
        if len(batch) == 500:
            deleted += _delete_batch(batch)
            batch.clear()
    if batch:
        deleted += _delete_batch(batch)
    return deleted


def _delete_batch(ids):
    # Keep pfSense block history even if its triggering alert is removed.
    """Lepaskan referensi riwayat blokir sebelum menghapus satu batch alert."""
    BlockedIP.query.filter(BlockedIP.alert_id.in_(ids)).update(
        {'alert_id': None}, synchronize_session=False,
    )
    deleted = Alert.query.filter(Alert.id.in_(ids)).delete(synchronize_session=False)
    # Keep all SOC deletions in one transaction; a failed batch must roll back
    # the whole local cleanup rather than leaving a partially purged cache.
    db.session.flush()
    return deleted


def reconcile(purge):
    """Periksa tugas Indexer lalu selesaikan atau catat kegagalan di SOC."""
    if purge.status != 'running' or not purge.task_id:
        return describe(purge)
    if not _reconcile_lock.acquire(blocking=False):
        return describe(purge)
    try:
        result = _indexer('GET', f'/_tasks/{quote(purge.task_id, safe=":")}', timeout=15)
        if not result.get('completed'):
            return describe(purge)
        response = result.get('response', {})
        if result.get('error') or response.get('failures') or response.get('timed_out') or response.get('version_conflicts'):
            raise RuntimeError('Indexer melaporkan kegagalan parsial; alert SOC dipertahankan untuk pemeriksaan')
        purge.indexer_deleted = int(response.get('deleted', 0))
        if purge.indexer_deleted != purge.expected_indexer:
            raise RuntimeError('Jumlah dokumen Indexer yang terhapus berbeda dari pratinjau; periksa Indexer sebelum mengulang')
        if _count_local(purge) != purge.expected_soc:
            raise RuntimeError('Jumlah salinan SOC berubah saat Indexer menghapus; salinan SOC dipertahankan untuk pemeriksaan')
        purge.soc_deleted = _finish_local(purge)
        purge.status = 'complete'
        purge.finished_at = _naive_now()
        db.session.add(AuditLog(
            action='purge_alerts',
            details=f'Selesai hapus alert lebih tua dari {purge.period}: Indexer={purge.indexer_deleted}, SOC={purge.soc_deleted}; riwayat blokir dipertahankan',
            performed_by=db.session.get(User, purge.user_id).username,
            result='success',
        ))
        db.session.commit()
    except Exception as error:
        db.session.rollback()
        purge.status = 'failed'
        purge.error = str(error)[:500]
        purge.finished_at = _naive_now()
        db.session.commit()
        try:
            create_audit_log(
                action='purge_alerts', details=f'Penghapusan {purge.id} perlu pemeriksaan',
                result='failure', error_message=purge.error,
            )
        except Exception:
            db.session.rollback()
            logger.exception('Could not write failure audit entry for alert purge %s', purge.id)
    finally:
        _reconcile_lock.release()
    return describe(purge)


def reconcile_running():
    """Lanjutkan pemeriksaan tugas aktif melalui scheduler dengan kunci proses."""
    for purge in AlertPurge.query.filter_by(status='running').all():
        reconcile(purge)
    stale = AlertPurge.query.filter_by(status='starting').filter(
        AlertPurge.started_at < _naive_now() - timedelta(minutes=5)
    ).all()
    for purge in stale:
        purge.status = 'failed'
        purge.error = 'Status awal tidak selesai; periksa tugas Indexer sebelum mengulang'
        purge.finished_at = _naive_now()
    if stale:
        db.session.commit()
