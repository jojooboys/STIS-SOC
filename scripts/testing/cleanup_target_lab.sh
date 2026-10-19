#!/usr/bin/env bash
# Remove only the temporary web1 test helper. Keep production logs, Wazuh
# collection/FIM, Website Guard, Apache access logging, and RemoteIP settings.
# Run on STIS after saving test evidence and cleaning isolated FIM test files.

set -euo pipefail

HELPER='/var/www/web1/lab_probe.php'
TOKEN='/etc/stis-soc-lab/probe-token'
LAB_CONF='/etc/apache2/conf-available/stis-soc-lab-probe.conf'
LAB_ENABLED='/etc/apache2/conf-enabled/stis-soc-lab-probe.conf'

if [ "$(id -u)" -ne 0 ]; then
    echo '[GAGAL] Jalankan dengan sudo atau sebagai root.' >&2
    exit 1
fi

# Refuse to remove files that may have been replaced by a real application or
# an unrelated Apache configuration since the lab was prepared.
if [ -e "$HELPER" ] && ! grep -Fqs 'STIS SOC lab-only event generator' "$HELPER"; then
    echo "[GAGAL] $HELPER bukan helper lab yang dikenal; periksa manual." >&2
    exit 1
fi
if [ -e "$LAB_CONF" ] && ! grep -Fqs 'STIS SOC functional-test helper' "$LAB_CONF"; then
    echo "[GAGAL] $LAB_CONF bukan konfigurasi lab yang dikenal; periksa manual." >&2
    exit 1
fi

if [ -L "$LAB_ENABLED" ]; then
    a2disconf stis-soc-lab-probe >/dev/null
fi
if ! apache2ctl configtest; then
    if [ -e "$LAB_CONF" ]; then
        a2enconf stis-soc-lab-probe >/dev/null
    fi
    echo '[GAGAL] Konfigurasi Apache tidak valid; periksa sebelum melanjutkan.' >&2
    exit 1
fi

# Remove the token-protected web endpoint before reloading Apache.
rm -f -- "$HELPER"
systemctl reload apache2
rm -f -- "$TOKEN" "$LAB_CONF"
rmdir /etc/stis-soc-lab 2>/dev/null || true

echo '[SELESAI] Helper, token, dan konfigurasi Apache lab lama dihapus.'
echo 'Monitoring produksi tetap aktif: CustomLog, RemoteIP, Agent, FIM, Website Guard, dan log bukti.'
if grep -RqsE '<Files[[:space:]]+"lab_probe\.php"' /etc/apache2/sites-enabled; then
    echo '[PERIKSA] Ada blok <Files "lab_probe.php"> lama pada VirtualHost; hapus manual jika hanya untuk uji.' >&2
fi
systemctl is-active apache2 wazuh-agent website-guard.timer
