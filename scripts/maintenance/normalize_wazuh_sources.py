#!/usr/bin/env python3
"""Review and remove proven duplicate Wazuh log sources on one host.

Run on the Agent host or Manager. The default is read-only; --apply backs up
ossec.conf, validates Wazuh, and rolls back if validation or restart fails.
This intentionally preserves application login logs and uncertain Apache logs.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


BLOCK = re.compile(r"(?m)^[ \t]*<localfile>.*?</localfile>[ \t]*\n?", re.S)
LOCATION = re.compile(r"<location>\s*(.*?)\s*</location>", re.S)
FORMAT = re.compile(r"<log_format>\s*(.*?)\s*</log_format>", re.S)
CANONICAL_APACHE = "/var/log/stis-soc/apache/*.access.log"
CANONICAL_APPS = "/var/log/stis-soc/apps/*.jsonl"
LEGACY_SITE = re.compile(r"/var/log/apache2/([A-Za-z0-9_-]+)_access\.log$")


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def apache_uses_canonical(slug: str, sites: Path) -> bool:
    expected = f"/var/log/stis-soc/apache/{slug}.access.log"
    if not sites.is_dir():
        return False
    for site in sites.iterdir():
        if not site.is_file():
            continue
        try:
            content = site.read_text(errors="replace")
        except OSError:
            continue
        if re.search(r"(?m)^\s*CustomLog\s+" + re.escape(expected) + r"\s+", content):
            return True
    return False


def normalize(content: str, role: str, sites: Path) -> tuple[str, list[str], list[str]]:
    removals: list[tuple[int, int]] = []
    changes: list[str] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    sources = {
        (match.group(1).strip(), (fmt.group(1).strip() if (fmt := FORMAT.search(block.group())) else ""))
        for block in BLOCK.finditer(content)
        if (match := LOCATION.search(block.group()))
    }
    if role == "agent" and (CANONICAL_APACHE, "apache") not in sources:
        raise ValueError(f"Jalur umum {CANONICAL_APACHE} dengan format apache belum ada; pasang sesuai Panduan 02 dahulu.")
    if role == "agent" and (CANONICAL_APPS, "json") not in sources:
        raise ValueError(f"Jalur umum {CANONICAL_APPS} dengan format json belum ada; pasang sesuai Panduan 02 dahulu.")
    if role == "agent" and ("/var/log/auth.log", "syslog") in sources and ("journald", "journald") in sources:
        warnings.append("auth.log dan journald mungkin memuat peristiwa SSH yang sama; bandingkan location alert sebelum menghapus salah satunya.")

    for block in BLOCK.finditer(content):
        location_match = LOCATION.search(block.group())
        if not location_match:
            continue
        location = location_match.group(1).strip()
        format_match = FORMAT.search(block.group())
        log_format = format_match.group(1).strip() if format_match else ""
        key = (location, log_format)
        reason = ""
        if key in seen:
            reason = f"entri identik berulang: {location} ({log_format})"
        else:
            seen.add(key)
            if role == "agent":
                old_site = LEGACY_SITE.fullmatch(location)
                if old_site:
                    slug = old_site.group(1)
                    if apache_uses_canonical(slug, sites):
                        reason = f"kolektor lama {location}; Apache memakai log umum {slug}.access.log"
                    else:
                        warnings.append(f"Pertahankan {location}: belum terbukti CustomLog umum aktif.")
                elif location == "/var/log/apache2/access.log":
                    warnings.append(
                        "Periksa /var/log/apache2/access.log: sumber ini bisa berisi situs lain; "
                        "hapus manual hanya setelah semua request sudah masuk log umum."
                    )
                elif location.endswith("/login_attempt.log"):
                    warnings.append(
                        f"Pertahankan {location}: migrasikan hanya setelah aplikasi menulis "
                        "event login setara ke JSONL umum."
                    )
            elif location.startswith("/var/log/apache2/"):
                if not Path(location).exists():
                    reason = f"kolektor Apache di Manager tidak punya file lokal: {location}"
                elif log_format == "syslog":
                    warnings.append(f"Periksa format {location}: file Apache aktif tetapi disetel syslog.")
        if reason:
            removals.append((block.start(), block.end()))
            changes.append(reason)

    if role == "agent" and "/var/www/web1</directories>" in content and "/var/www</directories>" in content:
        warnings.append(
            "FIM /var/www dan /var/www/web1 bertumpang tindih; atribut who-data "
            "web1 berbeda, jadi tidak dihapus otomatis. Tinjau sebelum menyatukannya."
        )
    for start, end in reversed(removals):
        content = content[:start] + content[end:]
    return content, changes, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("agent", "manager"), required=True)
    parser.add_argument("--config", type=Path, default=Path("/var/ossec/etc/ossec.conf"))
    parser.add_argument("--sites", type=Path, default=Path("/etc/apache2/sites-enabled"))
    parser.add_argument("--apply", action="store_true", help="Backup, apply, validate, and restart")
    args = parser.parse_args()
    if args.apply and os.geteuid() != 0:
        parser.error("--apply harus dijalankan dengan sudo/root")
    try:
        original = args.config.read_text()
        updated, changes, warnings = normalize(original, args.role, args.sites)
    except (OSError, ValueError) as error:
        print(f"[GAGAL] {error}", file=sys.stderr)
        return 2
    for change in changes:
        print(f"[HAPUS] {change}")
    for warning in warnings:
        print(f"[TINJAU] {warning}")
    if not changes:
        print("[OK] Tidak ada sumber log yang aman dihapus otomatis.")
        return 0
    if not args.apply:
        print("[INFO] Mode baca saja. Tambahkan --apply sesudah meninjau daftar di atas.")
        return 0

    backup = args.config.with_name(
        f"{args.config.name}.{datetime.now().strftime('%Y%m%d-%H%M%S')}.bak"
    )
    shutil.copy2(args.config, backup)
    service = "wazuh-agent" if args.role == "agent" else "wazuh-manager"
    try:
        args.config.write_text(updated)
        run(["/var/ossec/bin/wazuh-logcollector", "-t"])
        if args.role == "agent":
            run(["/var/ossec/bin/wazuh-agentd", "-t"])
            run(["/var/ossec/bin/wazuh-syscheckd", "-t"])
        else:
            run(["/var/ossec/bin/wazuh-analysisd", "-t"])
        run(["systemctl", "restart", service])
        run(["systemctl", "is-active", "--quiet", service])
    except (OSError, subprocess.CalledProcessError) as error:
        shutil.copy2(backup, args.config)
        print(f"[GAGAL] {error}; konfigurasi lama dipulihkan dari {backup}.", file=sys.stderr)
        subprocess.run(["systemctl", "restart", service], check=False)
        return 1
    print(f"[OK] Konfigurasi aktif. Backup: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
