#!/usr/bin/env python3
"""Detect website defacement and gambling/loan advertisement injection.

The program uses only Python's standard library so it can run on an Ubuntu web
server without installing packages. It writes flat JSON lines for Wazuh and
keeps an approved SHA-256 baseline. Detection is deliberately non-destructive:
an administrator reviews and restores a file before approving a new baseline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


# All websites under this root share the same scanner and baseline. A new
# /var/www/<slug> site is picked up without changing the systemd unit.
DEFAULT_ROOT = Path('/var/www')
DEFAULT_STATE_DIR = Path('/var/lib/mini-soc-website-guard')
DEFAULT_LOG = Path('/var/log/mini-soc/website_guard.log')
SCANNED_SUFFIXES = {
    '.html', '.htm', '.php', '.phtml', '.php3', '.php4', '.php5', '.php7',
    '.php8', '.phar', '.js', '.jsx', '.ts', '.tsx', '.css', '.json', '.xml',
    '.svg', '.txt', '.inc', '.conf', '.htaccess',
}
SKIPPED_DIRS = {'.git', 'cache', 'logs', 'node_modules', 'sessions', 'tmp', 'vendor'}
MAX_TEXT_BYTES = 3 * 1024 * 1024

CONTENT_PATTERNS = {
    # High-signal PHP obfuscation chains are review-only findings. Their
    # presence alone does not identify the remote actor who wrote the file.
    'webshell_code': (
        re.compile(r'\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate)\s*\(', re.IGNORECASE),
    ),
    'gambling_spam': (
        re.compile(
            r'\b(?:judi\s*online|slot\s*(?:online|gacor)|togel\s*online|'
            r'casino\s*online|situs\s*slot|pragmatic\s*play|bonus\s*new\s*member)\b',
            re.IGNORECASE,
        ),
    ),
    'loan_spam': (
        re.compile(
            r'\b(?:pinjol|pinjaman\s*online|pinjaman\s*cair\s*cepat|'
            r'dana\s*cepat|kredit\s*online\s*tanpa\s*jaminan)\b',
            re.IGNORECASE,
        ),
    ),
}


def utc_now() -> str:
    """Buat timestamp UTC untuk event JSONL Wazuh."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def sha256_file(path: Path) -> str:
    """Hitung hash bertahap agar seluruh file tidak perlu dimuat ke memori."""
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def should_scan(relative_path: Path) -> bool:
    """Pilih ekstensi website dan abaikan direktori nonkonten."""
    if any(part in SKIPPED_DIRS for part in relative_path.parts[:-1]):
        return False
    name = relative_path.name.lower()
    return relative_path.suffix.lower() in SCANNED_SUFFIXES or name == '.htaccess'


def inspect_tree(root: Path) -> tuple[dict[str, dict], list[dict]]:
    """Return current inventory and suspicious-content findings."""
    inventory: dict[str, dict] = {}
    findings: list[dict] = []
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        relative_text = relative.as_posix()
        if any(part in SKIPPED_DIRS for part in relative.parts):
            continue
        if path.is_symlink():
            inventory[relative_text] = {
                'kind': 'symlink',
                'target': os.readlink(path),
            }
            continue
        if not path.is_file() or not should_scan(relative):
            continue
        try:
            size = path.stat().st_size
            digest = sha256_file(path)
        except (OSError, PermissionError) as error:
            findings.append({
                'event_type': 'web_scanner_error',
                'file_path': str(path),
                'error': str(error),
            })
            continue
        inventory[relative_text] = {
            'kind': 'file',
            'sha256': digest,
            'size': size,
        }
        if size > MAX_TEXT_BYTES:
            continue
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except (OSError, PermissionError) as error:
            findings.append({
                'event_type': 'web_scanner_error',
                'file_path': str(path),
                'error': str(error),
            })
            continue
        for threat_type, patterns in CONTENT_PATTERNS.items():
            matches = sorted({
                match.group(0).lower().replace(' ', '_')
                for pattern in patterns for match in pattern.finditer(content)
            })
            if matches:
                findings.append({
                    'event_type': 'web_content_threat',
                    'threat_type': threat_type,
                    'file_path': str(path),
                    'file_hash': digest,
                    'matched_terms': ','.join(matches[:10]),
                })
    return inventory, findings


def compare_inventory(baseline: dict[str, dict], current: dict[str, dict], root: Path) -> list[dict]:
    """Bandingkan inventaris saat ini dengan baseline untuk mencari perubahan."""
    changes: list[dict] = []
    for relative in sorted(set(baseline) | set(current)):
        old = baseline.get(relative)
        new = current.get(relative)
        if old == new:
            continue
        if old is None:
            change_type = 'symlink' if new.get('kind') == 'symlink' else 'added'
        elif new is None:
            change_type = 'deleted'
        elif new.get('kind') == 'symlink':
            change_type = 'symlink'
        else:
            change_type = 'modified'
        changes.append({
            'event_type': 'web_integrity_change',
            'change_type': change_type,
            'file_path': str(root / relative),
            'file_hash': (new or {}).get('sha256', '-'),
        })
    return changes


def finding_key(event: dict) -> str:
    """Buat identitas temuan untuk menekan pelaporan duplikat."""
    material = json.dumps(event, sort_keys=True, ensure_ascii=True).encode('utf-8')
    return hashlib.sha256(material).hexdigest()


def load_json(path: Path, default):
    """Baca state JSON lokal menggunakan nilai default bila file belum ada."""
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return default
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f'Cannot read {path}: {error}') from error


def atomic_write_json(path: Path, value) -> None:
    """Tulis state ke file sementara lalu ganti tujuan secara atomik."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n',
        encoding='utf-8',
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def append_events(log_path: Path, events: list[dict]) -> None:
    """Tambahkan temuan sebagai satu objek JSON per baris untuk Agent."""
    if not events:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open('a', encoding='utf-8') as handle:
        for event in events:
            payload = {'timestamp': utc_now(), **event}
            handle.write(json.dumps(payload, separators=(',', ':'), ensure_ascii=False) + '\n')
    os.chmod(log_path, 0o640)


def scan(root: Path, baseline_path: Path, seen_path: Path, log_path: Path) -> dict:
    """Baca baseline, pindai file, dan laporkan hanya perubahan/temuan yang perlu dicatat."""
    baseline_document = load_json(baseline_path, None)
    if not baseline_document:
        raise RuntimeError(f'Baseline not found: run init first ({baseline_path})')
    if Path(baseline_document.get('root', '')) != root:
        raise RuntimeError('Baseline root does not match the configured website root')

    current, content_findings = inspect_tree(root)
    integrity_findings = compare_inventory(baseline_document.get('files', {}), current, root)
    findings = content_findings + integrity_findings
    previous_seen = set(load_json(seen_path, {}).get('keys', []))
    current_by_key = {finding_key(item): item for item in findings}
    new_events = [item for key, item in current_by_key.items() if key not in previous_seen]
    append_events(log_path, new_events)
    atomic_write_json(seen_path, {'updated_at': utc_now(), 'keys': sorted(current_by_key)})
    return {
        'status': 'threats_found' if findings else 'clean',
        'root': str(root),
        'files_scanned': len(current),
        'findings': len(findings),
        'new_events': len(new_events),
        'log': str(log_path),
    }


def create_baseline(root: Path, baseline_path: Path, seen_path: Path, force: bool = False) -> dict:
    """Simpan inventaris yang disetujui operator sebagai acuan berikutnya."""
    current, findings = inspect_tree(root)
    content_findings = [item for item in findings if item.get('event_type') == 'web_content_threat']
    if content_findings and not force:
        terms = ', '.join(sorted({item['threat_type'] for item in content_findings}))
        raise RuntimeError(f'Refusing to approve suspicious content: {terms}')
    document = {
        'version': 1,
        'created_at': utc_now(),
        'root': str(root),
        'files': current,
    }
    atomic_write_json(baseline_path, document)
    atomic_write_json(seen_path, {'updated_at': utc_now(), 'keys': []})
    return {
        'status': 'baseline_created',
        'root': str(root),
        'files': len(current),
        'baseline': str(baseline_path),
    }


def parse_args(argv=None):
    """Baca opsi root website, state, log, dan operasi baseline/scan."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('init', 'check', 'approve'))
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    parser.add_argument('--state-dir', type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument('--log', type=Path, default=DEFAULT_LOG)
    parser.add_argument(
        '--force', action='store_true',
        help='Approve a baseline even if suspicious content is present (not recommended).',
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    """Pilih operasi scanner dan kembalikan status ke shell/systemd."""
    args = parse_args(argv)
    root = args.root.resolve()
    baseline_path = args.state_dir / 'baseline.json'
    seen_path = args.state_dir / 'seen.json'
    try:
        if not root.is_dir():
            raise RuntimeError(f'Website root does not exist: {root}')
        if args.command in ('init', 'approve'):
            result = create_baseline(root, baseline_path, seen_path, force=args.force)
        else:
            result = scan(root, baseline_path, seen_path, args.log)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'error', 'message': str(error)}, indent=2), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
