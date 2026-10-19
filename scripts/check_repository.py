"""Periksa kandidat publikasi Git, sintaks Python/XML, dataset, dan tautan lokal.

Tidak mencetak isi rahasia. Pemeriksaan pola kredensial adalah pengaman dasar,
bukan pengganti peninjauan isi file dan riwayat commit oleh pemilik repositori.
"""

import ast
import csv
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', 'node_modules', 'venv', '__pycache__', 'dist', 'instance', 'reports', 'catatan_pribadi'}
SECRET_PATTERNS = [
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    r'\bgh[pousr]_[A-Za-z0-9]{30,}\b',
    r'\bgithub_pat_[A-Za-z0-9_]{40,}\b',
    r'\bAKIA[A-Z0-9]{16}\b',
]


def candidates():
    """Git adalah acuan agar file lokal yang diabaikan tidak ikut diperiksa."""
    result = subprocess.run(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
        cwd=ROOT, capture_output=True,
    )
    if result.returncode:
        raise RuntimeError('Jalankan git init -b main dahulu agar aturan .gitignore dapat diperiksa.')
    return sorted({ROOT / name.decode('utf-8') for name in result.stdout.split(b'\0') if name})


def check_links(path, text):
    """Periksa tujuan tautan Markdown relatif; fragmen heading tidak diperiksa."""
    issues = []
    # Abaikan code fence agar pola contoh dan potongan source tidak dianggap tautan.
    prose = re.sub(r'^```[^\n]*\n.*?^```[^\n]*$', '', text, flags=re.M | re.S)
    for target in re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)', prose):
        target = target.strip().split(' "', 1)[0].strip('<>')
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        resolved = path.parent / unquote(parsed.path)
        if resolved.resolve().is_relative_to(ROOT / 'catatan_pribadi'):
            issues.append(f'{path.relative_to(ROOT)}: tautan publik mengarah ke catatan pribadi: {target}')
        if not resolved.exists():
            issues.append(f'{path.relative_to(ROOT)}: tautan lokal tidak ada: {target}')
    return issues


def main():
    """Kembalikan status gagal jika kandidat publikasi berisi masalah material."""
    issues = []
    paths = candidates()
    for path in paths:
        relative = path.relative_to(ROOT)
        parts = relative.parts
        excluded = any(p in EXCLUDED or p.startswith('.venv') for p in parts)
        private = path.name.startswith('.env') and path.name != '.env.example'
        if excluded or private or path.suffix.lower() in {'.db', '.sqlite', '.sqlite3', '.pem', '.key', '.docx', '.gz'}:
            issues.append(f'{relative}: file lokal/privat/generated masuk kandidat Git')
            continue
        if not path.is_file():
            issues.append(f'{relative}: file dalam index tidak ditemukan')
            continue
        if path.stat().st_size > 10 * 1024 * 1024:
            issues.append(f'{relative}: lebih dari 10 MiB; tinjau sebelum publikasi')
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            issues.append(f'{relative}: bukan teks UTF-8; tinjau file binary secara manual')
            continue
        if any(re.search(pattern, text) for pattern in SECRET_PATTERNS):
            issues.append(f'{relative}: pola kredensial privat terdeteksi; nilai disembunyikan')
        if path.suffix == '.py':
            try:
                ast.parse(text, filename=str(relative))
            except SyntaxError as error:
                issues.append(f'{relative}:{error.lineno}: sintaks Python tidak valid')
        elif path.suffix == '.xml':
            try:
                # Wazuh dapat memuat beberapa elemen top-level dalam satu file.
                ET.fromstring(f'<repository_check>{text}</repository_check>')
            except ET.ParseError as error:
                issues.append(f'{relative}: XML tidak valid: {error}')
        elif path.suffix == '.md':
            issues.extend(check_links(path, text))
    with (ROOT / 'datasets/dummy/alerts.csv').open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) < 5:
        issues.append('Dataset dummy harus memiliki minimal lima baris data')
    for row in rows:
        if not row['full_log'].startswith('SYNTHETIC') or 'USER_MASKED' not in row['full_log']:
            issues.append(f"Dataset {row['alert_id']}: penanda sintetis/masking tidak lengkap")
    if issues:
        print('\n'.join(issues))
        return 1
    print(f'OK: {len(paths)} kandidat file Git; sintaks Python/XML, tautan lokal, dan {len(rows)} baris dummy diperiksa.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
