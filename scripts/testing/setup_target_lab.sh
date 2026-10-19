#!/usr/bin/env bash
# Install the lab-only PHP event helper on the STIS target server.
# The helper rejects test input and only writes JSONL evidence for Wazuh.
# Usage:
#   sudo bash setup_target_lab.sh HAPROXY_IP WEB_ROOT DOMAIN

set -u
set -o pipefail

# Accept the old four-argument form once so an existing command does not break.
# Its first argument was the Kali IP and is intentionally ignored now.
if [ "$#" -ge 4 ]; then
    echo '[INFO] Format lama terdeteksi; IP Kali tidak lagi disimpan pada Apache.'
    shift
fi
HAPROXY_IP="${1:-10.10.10.1}"
WEB_ROOT="${2:-/var/www/web1}"
LAB_DOMAIN="${3:-web1.stis.local}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_SOURCE="$SCRIPT_DIR/lab_probe.php"
APACHE_LAB_CONF='/etc/apache2/conf-available/stis-soc-lab-probe.conf'
APACHE_LOGGING_CONF='/etc/apache2/conf-available/stis-soc-logging.conf'
TOKEN_FILE='/etc/stis-soc-lab/probe-token'
ASSET_SLUG="$(basename "$WEB_ROOT")"
JSON_LOG="/var/log/stis-soc/apps/${ASSET_SLUG}.jsonl"
ACCESS_LOG="/var/log/stis-soc/apache/${ASSET_SLUG}.access.log"

fail() {
    echo "[GAGAL] $*" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    fail 'Jalankan dengan sudo atau sebagai root.'
fi

[[ "$HAPROXY_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail 'Format HAPROXY_IP bukan IPv4.'
test -f "$HELPER_SOURCE" || fail "Salin lab_probe.php ke $SCRIPT_DIR terlebih dahulu."
test -d "$WEB_ROOT" || fail "Web root tidak ditemukan: $WEB_ROOT"
[ "$WEB_ROOT" = '/var/www/web1' ] && [ "$LAB_DOMAIN" = 'web1.stis.local' ] || \
    fail 'Helper PHP contoh ini memakai web1 secara tetap; gunakan /var/www/web1 dan web1.stis.local.'
command -v apache2ctl >/dev/null 2>&1 || fail 'Apache belum terpasang.'
command -v php >/dev/null 2>&1 || fail 'PHP CLI belum terpasang.'
test -x /var/ossec/bin/wazuh-agentd || fail 'Wazuh Agent belum terpasang.'

echo '[1/7] Siapkan log JSONL aplikasi...'
install -d -m 0755 /var/log/stis-soc/apps
install -d -m 0755 /var/log/stis-soc/apache
touch "$JSON_LOG"
chown www-data:www-data "$JSON_LOG"
chmod 0640 "$JSON_LOG"
touch "$ACCESS_LOG"
chmod 0640 "$ACCESS_LOG"

echo '[2/7] Siapkan token privat...'
install -d -o root -g www-data -m 0750 /etc/stis-soc-lab
if [ ! -s "$TOKEN_FILE" ]; then
    umask 0077
    openssl rand -hex 24 > "$TOKEN_FILE" || fail 'Gagal membuat token.'
fi
chown root:www-data "$TOKEN_FILE"
chmod 0640 "$TOKEN_FILE"

echo '[3/7] Pasang helper PHP...'
install -o root -g www-data -m 0640 "$HELPER_SOURCE" "$WEB_ROOT/lab_probe.php"
php -l "$WEB_ROOT/lab_probe.php" || fail 'Sintaks helper PHP tidak valid.'

echo '[4/7] Hapus pembatas IP lama; helper dilindungi token privat...'
if [ -e "$APACHE_LAB_CONF" ] &&
   ! grep -Fqs 'STIS SOC functional-test helper' "$APACHE_LAB_CONF"; then
    fail "$APACHE_LAB_CONF bukan konfigurasi lab yang dikenal; periksa manual."
fi
if [ -L /etc/apache2/conf-enabled/stis-soc-lab-probe.conf ]; then
    a2disconf stis-soc-lab-probe >/dev/null || fail 'Gagal menonaktifkan pembatas IP lama.'
    if ! apache2ctl configtest; then
        a2enconf stis-soc-lab-probe >/dev/null || true
        fail 'Konfigurasi Apache tidak valid; pembatas IP lama dipulihkan.'
    fi
fi
rm -f -- "$APACHE_LAB_CONF"
a2enmod remoteip >/dev/null || fail 'Gagal mengaktifkan mod_remoteip.'

echo '[5/7] Periksa konfigurasi IP asli dari HAProxy...'
if [ -s "$APACHE_LOGGING_CONF" ]; then
    a2enconf stis-soc-logging >/dev/null || fail 'Gagal mengaktifkan konfigurasi log yang sudah ada.'
fi
if ! grep -RqsE '^[[:space:]]*LogFormat.*[[:space:]]stis_soc_combined[[:space:]]*$' \
    /etc/apache2/apache2.conf /etc/apache2/conf-enabled /etc/apache2/sites-enabled; then
    printf '%s\n' 'LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" stis_soc_combined' \
        >> "$APACHE_LOGGING_CONF"
fi
if ! grep -RqsE '^[[:space:]]*RemoteIPHeader[[:space:]]+X-Forwarded-For' \
    /etc/apache2/apache2.conf /etc/apache2/conf-enabled /etc/apache2/sites-enabled; then
    printf '%s\n' 'RemoteIPHeader X-Forwarded-For' >> "$APACHE_LOGGING_CONF"
    echo "RemoteIPHeader ditambahkan untuk HAProxy $HAPROXY_IP."
fi
if ! grep -RhsE '^[[:space:]]*RemoteIPInternalProxy[[:space:]]+' \
    /etc/apache2/apache2.conf /etc/apache2/conf-enabled /etc/apache2/sites-enabled | \
    awk -v ip="$HAPROXY_IP" '$2 == ip { found=1 } END { exit !found }'; then
    printf 'RemoteIPInternalProxy %s\n' "$HAPROXY_IP" >> "$APACHE_LOGGING_CONF"
fi
if [ -s "$APACHE_LOGGING_CONF" ]; then
    a2enconf stis-soc-logging >/dev/null || fail 'Gagal mengaktifkan konfigurasi log STIS SOC.'
fi

echo '[6/7] Validasi dan reload Apache...'
apache2ctl configtest || fail 'Konfigurasi Apache tidak valid; Apache tidak direload.'
systemctl reload apache2 || fail 'Apache gagal direload.'
runuser -u www-data -- test -w "$JSON_LOG" || fail "www-data tidak dapat menulis $JSON_LOG"

echo '[7/7] Periksa konfigurasi pengumpulan Wazuh Agent...'
missing=0
if ! grep -qs '/var/log/stis-soc/apps/\*\.jsonl' /var/ossec/etc/ossec.conf; then
    echo '[PERLU SETTING] ossec.conf belum mengoleksi /var/log/stis-soc/apps/*.jsonl'
    missing=1
fi
if ! grep -qs '/var/log/stis-soc/apache/\*\.access.log' /var/ossec/etc/ossec.conf; then
    echo '[PERLU SETTING] ossec.conf belum mengoleksi /var/log/stis-soc/apache/*.access.log'
    missing=1
fi
if ! grep -qsE '<directories[^>]*>[^<]*/var/www[^<]*</directories>' /var/ossec/etc/ossec.conf; then
    echo '[PERLU SETTING] syscheck ossec.conf belum memantau /var/www'
    missing=1
fi
if ! grep -RqsF "CustomLog $ACCESS_LOG stis_soc_combined" /etc/apache2/sites-enabled; then
    echo "[PERLU SETTING] VirtualHost belum memiliki: CustomLog $ACCESS_LOG stis_soc_combined"
    missing=1
fi

echo
echo "Domain lab : $LAB_DOMAIN"
echo "Helper     : $WEB_ROOT/lab_probe.php"
echo "Log JSONL  : $JSON_LOG"
echo "Log Apache : $ACCESS_LOG"
echo "Token      : $TOKEN_FILE"
echo 'IP penguji : dinamis; tidak disimpan pada konfigurasi Apache'
if [ "$missing" -eq 0 ]; then
    /var/ossec/bin/wazuh-agentd -t || fail 'Konfigurasi Wazuh Agent tidak valid.'
    /var/ossec/bin/wazuh-logcollector -t || fail 'Konfigurasi logcollector tidak valid.'
    systemctl restart wazuh-agent || fail 'Wazuh Agent gagal direstart.'
    echo '[SELESAI] Target siap. Tampilkan token dengan:'
    echo "  sudo cat $TOKEN_FILE"
else
    echo '[BELUM SELESAI] Tambahkan blok Wazuh Agent dari panduan, validasi, lalu jalankan ulang skrip ini.'
    exit 2
fi
