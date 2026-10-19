#!/usr/bin/env bash
# Optional: enrich website FIM alerts with VirusTotal hash reputation.
# Requires the operator's own API key; no file removal or IP block is enabled.
set -euo pipefail

CONF='/var/ossec/etc/ossec.conf'
[ "$(id -u)" -eq 0 ] || { echo 'Jalankan sebagai root pada Wazuh Manager.' >&2; exit 1; }
[ -f "$CONF" ] || { echo "Tidak ada $CONF" >&2; exit 1; }
if grep -Eq '<name>[[:space:]]*virustotal[[:space:]]*</name>' "$CONF"; then
    echo 'VirusTotal sudah dikonfigurasi. Periksa blok yang ada; skrip tidak akan menggandakannya.'
    exit 0
fi

read -rsp 'VirusTotal API key (tidak ditampilkan): ' VT_KEY
echo
[[ "$VT_KEY" =~ ^[[:alnum:]]{16,128}$ ]] || {
    unset VT_KEY
    echo 'Format API key tidak sesuai; konfigurasi tidak diubah.' >&2
    exit 1
}
backup="${CONF}.$(date +%Y%m%d-%H%M%S).bak"
cp -a -- "$CONF" "$backup"
umask 0077
cat >> "$CONF" <<EOF

<ossec_config>
  <integration>
    <name>virustotal</name>
    <api_key>${VT_KEY}</api_key>
    <rule_id>100304</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
unset VT_KEY

if ! /var/ossec/bin/wazuh-analysisd -t || ! systemctl restart wazuh-manager; then
    cp -a -- "$backup" "$CONF"
    systemctl restart wazuh-manager || true
    echo "Konfigurasi gagal; dipulihkan dari $backup" >&2
    exit 1
fi
echo 'VirusTotal aktif untuk rule FIM website 100304. Ini hanya deteksi hash; tidak menghapus file.'
echo 'Periksa /var/ossec/logs/integrations.log dan alert rule 87105 setelah perubahan file uji.'
