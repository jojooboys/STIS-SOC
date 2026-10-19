#!/usr/bin/env bash
# Read-only checks for the STIS web1 target. Run on the STIS server.
# Default "lab" requires the temporary PHP probe. "production" checks the
# permanent monitoring path after cleanup without requiring the probe/token.
set -u

failures=0
HAPROXY_IP="${LAB_HAPROXY_IP:-10.10.10.1}"
MODE="${1:-lab}"

if [ "$MODE" != lab ] && [ "$MODE" != production ]; then
    echo 'Pemakaian: sudo bash check_target_readiness.sh [lab|production]' >&2
    exit 2
fi

pass() { printf '[OK] %s\n' "$1"; }
fail() { printf '[PERLU PERBAIKAN] %s\n' "$1"; failures=$((failures + 1)); }

check_service() {
    if systemctl is-active --quiet "$1"; then
        pass "$1 aktif"
    else
        fail "$1 tidak aktif"
    fi
}

check_literal() {
    if grep -Fqs -- "$2" "$1"; then
        pass "$3"
    else
        fail "$3; tidak ditemukan pada $1"
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    printf 'Jalankan sebagai root: sudo bash %s\n' "$0" >&2
    exit 2
fi

echo '=== Layanan dan file ==='
check_service apache2
check_service wazuh-agent
if [ -d /var/www/web1 ]; then pass 'Web root /var/www/web1 ada'; else fail 'Web root /var/www/web1 tidak ada'; fi
if [ "$MODE" = lab ]; then
    if [ -f /var/www/web1/lab_probe.php ]; then pass 'Helper lab_probe.php terpasang'; else fail 'Helper lab_probe.php belum terpasang'; fi
    if grep -RqsE '^[[:space:]]*Require[[:space:]]+ip[[:space:]]+' \
        /etc/apache2/conf-enabled/stis-soc-lab-probe.conf 2>/dev/null; then
        fail 'Pembatas IP lama untuk lab_probe.php masih aktif; jalankan ulang setup_target_lab.sh terbaru'
    else
        pass 'Helper tidak terikat pada IP Kali; autentikasi memakai token privat'
    fi
else
    if [ ! -e /var/www/web1/lab_probe.php ] && \
        [ ! -e /etc/stis-soc-lab/probe-token ] && \
        [ ! -e /etc/apache2/conf-available/stis-soc-lab-probe.conf ] && \
        [ ! -e /etc/apache2/conf-enabled/stis-soc-lab-probe.conf ] && \
        [ ! -L /etc/apache2/conf-enabled/stis-soc-lab-probe.conf ]; then
        pass 'Helper, token, dan konfigurasi Apache khusus lab sudah dibersihkan'
    else
        fail 'Masih ada helper, token, atau konfigurasi Apache khusus lab'
    fi
fi
if [ -x /usr/local/sbin/website_guard.py ]; then
    pass 'Website Guard terpasang'
    if systemctl is-active --quiet website-guard.timer; then
        pass 'Website Guard timer aktif'
    else
        fail 'Website Guard timer belum aktif; scan konten otomatis belum berjalan'
    fi
else
    fail 'Website Guard belum terpasang; uji judol/pinjol dan konten webshell belum siap'
fi

echo '=== Apache ==='
if apache2ctl configtest; then pass 'Sintaks Apache valid'; else fail 'Sintaks Apache tidak valid'; fi
if apache2ctl -M 2>/dev/null | grep -Fq remoteip_module; then
    pass 'mod_remoteip aktif'
else
    fail 'mod_remoteip belum aktif'
fi
if apache2ctl -S 2>&1 | grep -Fq web1.stis.local; then
    pass 'VirtualHost web1.stis.local aktif'
else
    fail 'VirtualHost web1.stis.local belum aktif'
fi
if grep -RqsF 'CustomLog /var/log/stis-soc/apache/web1.access.log stis_soc_combined' \
    /etc/apache2/sites-enabled; then
    pass 'CustomLog web1 memakai format STIS SOC'
else
    fail 'CustomLog web1 belum memakai /var/log/stis-soc/apache/web1.access.log'
fi
if grep -RqsE '^[[:space:]]*RemoteIPHeader[[:space:]]+X-Forwarded-For' \
    /etc/apache2/apache2.conf /etc/apache2/conf-enabled /etc/apache2/sites-enabled; then
    pass 'RemoteIPHeader X-Forwarded-For aktif'
else
    fail 'RemoteIPHeader X-Forwarded-For belum aktif'
fi
if grep -RhsE '^[[:space:]]*RemoteIPInternalProxy[[:space:]]+' \
    /etc/apache2/apache2.conf /etc/apache2/conf-enabled /etc/apache2/sites-enabled | \
    awk -v ip="$HAPROXY_IP" '$2 == ip { found=1 } END { exit !found }'; then
    pass "HAProxy $HAPROXY_IP dipercaya oleh mod_remoteip"
else
    fail "RemoteIPInternalProxy $HAPROXY_IP belum aktif; set LAB_HAPROXY_IP jika IP berbeda"
fi

echo '=== PHP dan log aplikasi ==='
if apache2ctl -M 2>/dev/null | grep -Eq 'php[0-9]*_module|proxy_fcgi_module'; then
    pass 'Apache mempunyai handler PHP; respons HTTP tetap perlu diuji dari Kali'
else
    fail 'Apache belum mempunyai handler PHP (mod_php atau proxy_fcgi/PHP-FPM)'
fi
if [ "$MODE" = lab ]; then
    if command -v php >/dev/null 2>&1 && [ -f /var/www/web1/lab_probe.php ] && \
        php -l /var/www/web1/lab_probe.php; then
        pass 'Sintaks helper PHP valid'
    else
        fail 'PHP CLI/helper tidak siap'
    fi
    if [ -s /etc/stis-soc-lab/probe-token ]; then
        pass 'Token helper tersedia (nilainya tidak dicetak)'
    else
        fail 'Token helper belum tersedia'
    fi
fi
if runuser -u www-data -- test -w /var/log/stis-soc/apps/web1.jsonl; then
    pass 'www-data dapat menulis web1.jsonl'
else
    fail 'www-data tidak dapat menulis web1.jsonl'
fi

echo '=== Wazuh Agent ==='
if [ -f /var/ossec/etc/ossec.conf ]; then
    check_literal /var/ossec/etc/ossec.conf '/var/log/stis-soc/apache/*.access.log' 'Koleksi access log Apache'
    check_literal /var/ossec/etc/ossec.conf '/var/log/stis-soc/apps/*.jsonl' 'Koleksi JSONL aplikasi'
    check_literal /var/ossec/etc/ossec.conf '/var/log/mini-soc/website_guard.log' 'Koleksi Website Guard'
    if grep -Eq '<directories[^>]*>[^<]*/var/www[^<]*</directories>' /var/ossec/etc/ossec.conf; then
        pass 'FIM memantau /var/www'
    else
        fail 'FIM belum memantau /var/www'
    fi
else
    fail 'Konfigurasi Wazuh Agent tidak ditemukan'
fi
if [ -x /var/ossec/bin/wazuh-agentd ] && /var/ossec/bin/wazuh-agentd -t; then
    pass 'Konfigurasi wazuh-agentd valid'
else
    fail 'Konfigurasi wazuh-agentd tidak valid'
fi
if [ -x /var/ossec/bin/wazuh-logcollector ] && /var/ossec/bin/wazuh-logcollector -t; then
    pass 'Konfigurasi wazuh-logcollector valid'
else
    fail 'Konfigurasi wazuh-logcollector tidak valid'
fi

echo '=== Hasil ==='
printf 'Mode: %s\n' "$MODE"
printf 'Perlu perbaikan: %s\n' "$failures"
echo 'Skrip ini belum membuktikan jalur HAProxy, IP klien asli, atau alert Manager.'
echo 'Lanjutkan dengan satu request dari Kali dan periksa baris log serta rule di Manager.'
[ "$failures" -eq 0 ]
