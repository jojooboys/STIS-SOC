#!/usr/bin/env bash
# Run one safe STIS SOC web detection scenario from Kali Linux.
# Examples:
#   bash run_web_attack_tests.sh list
#   bash run_web_attack_tests.sh sqli
#   bash run_web_attack_tests.sh webshell

set -u
set -o pipefail

CASE_NAME="${1:-list}"
LAB_WAN="${LAB_WAN:-}"
LAB_HOST="${LAB_HOST:-web1.stis.local}"

show_list() {
    cat <<'EOF'
Kasus yang tersedia:
  auth-bruteforce  -> 100500 lalu 100501 (butuh LAB_TOKEN)
  sqli             -> 100510 (butuh LAB_TOKEN)
  webshell         -> 100400 lalu 100401
  wordpress        -> 100410 lalu 100411 setelah 8 probe/IP/120 detik
  scanner          -> 100420 lalu 100421
  sensitive-file   -> 100430
  rce              -> 100440
  recon            -> 100450 lalu 100451
  traversal        -> 100460
  xss              -> 100468/100469 (HTTP 404/200), lalu 100470
  shellshock       -> 100490 atau rule bawaan 31168/31169
  ssrf-once        -> 100480 level 8; belum mencapai ambang blokir 10
  ssrf             -> 100480 lalu 100481 setelah 5 probe/IP/3600 detik
  http400          -> 31151 bila korelasi bawaan terpicu (butuh LAB_TOKEN)

Jalankan satu kasus, tunggu alert, dan simpan bukti. Bila IP Kali terblokir,
Unblock di dashboard sebelum menjalankan kasus berikutnya.
EOF
}

require_token() {
    if [ -z "${LAB_TOKEN:-}" ]; then
        read -rsp 'Token lab_probe.php: ' LAB_TOKEN
        echo
    fi
}

soc_get() {
    curl -g --path-as-is --connect-timeout 3 --max-time 8 \
        -sS -o /dev/null -w 'HTTP %{http_code}\n' \
        -H "Host: ${LAB_HOST}" "${LAB_URL}$1"
}

post_probe() {
    local mode="$1"
    local username="$2"
    curl --connect-timeout 3 --max-time 8 -sS -o /dev/null \
        -w 'HTTP %{http_code}\n' \
        -H "Host: ${LAB_HOST}" \
        -H "X-STIS-SOC-Lab-Token: ${LAB_TOKEN}" \
        --data-urlencode "mode=${mode}" \
        --data-urlencode "username=${username}" \
        "${LAB_URL}/lab_probe.php"
}

if [ "$CASE_NAME" = list ] || [ "$CASE_NAME" = help ] || [ "$CASE_NAME" = '--help' ]; then
    show_list
    exit 0
fi

if [ -z "$LAB_WAN" ]; then
    echo 'Set LAB_WAN ke IP WAN pfSense saat ini, misalnya:' >&2
    echo '  LAB_WAN=192.168.18.99 LAB_HOST=web1.stis.local bash run_web_attack_tests.sh webshell' >&2
    exit 2
fi
if ! [[ "$LAB_WAN" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "LAB_WAN bukan alamat IPv4: $LAB_WAN" >&2
    exit 2
fi
LAB_URL="http://${LAB_WAN}"

echo "Mulai    : $(date --iso-8601=seconds)"
echo "Kasus    : $CASE_NAME"
echo "Target   : $LAB_URL (Host: $LAB_HOST)"
echo "IP Kali  : $(ip -4 route get "$LAB_WAN" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')"
echo

case "$CASE_NAME" in
    auth-bruteforce)
        require_token
        for _n in 1 2 3 4 5; do post_probe auth-failed lab-admin; done
        ;;
    sqli)
        require_token
        post_probe sqli "admin' OR '1'='1' -- "
        ;;
    webshell)
        for _n in 1 2 3 4 5; do soc_get '/radio.php'; done
        ;;
    wordpress)
        for _n in 1 2 3 4 5 6 7 8; do soc_get '/wp-login.php'; done
        ;;
    scanner)
        for _n in 1 2 3 4 5 6 7 8 9 10; do
            curl --connect-timeout 3 --max-time 8 -sS -o /dev/null \
                -w 'HTTP %{http_code}\n' -H "Host: ${LAB_HOST}" \
                -A 'nuclei/3.0 STIS-SOC-lab' "${LAB_URL}/not-found"
        done
        ;;
    sensitive-file)
        soc_get '/.env'
        ;;
    rce)
        soc_get '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
        ;;
    recon)
        for _n in 1 2 3 4 5; do soc_get '/manager/html'; done
        ;;
    traversal)
        soc_get '/download?file=%2e%2e%2fetc%2fpasswd'
        ;;
    xss)
        for _n in 1 2 3 4 5; do
            soc_get '/?q=%3Cscript%3Ealert(1)%3C/script%3E'
        done
        ;;
    shellshock)
        curl --connect-timeout 3 --max-time 8 -sS -o /dev/null \
            -w 'HTTP %{http_code}\n' -H "Host: ${LAB_HOST}" \
            -A '() { :; }; echo STIS_SOC_TEST' \
            "${LAB_URL}/cgi-bin/test.sh"
        ;;
    ssrf-once)
        soc_get '/stis-soc-test-ssrf?url=http%3A%2F%2F127.0.0.1%3A9%2F'
        ;;
    ssrf)
        for _n in 1 2 3 4 5; do
            soc_get '/stis-soc-test-ssrf?url=http%3A%2F%2F127.0.0.1%3A9%2F'
        done
        ;;
    http400)
        require_token
        for _n in 1 2 3 4 5 6 7 8 9 10; do
            post_probe unknown test
        done
        ;;
    *)
        echo "Kasus tidak dikenal: $CASE_NAME" >&2
        show_list >&2
        exit 2
        ;;
esac

unset LAB_TOKEN 2>/dev/null || true
echo
echo "Selesai  : $(date --iso-8601=seconds)"
echo 'Tunggu interval polling SOC, tekan Fetch New Alerts, lalu periksa:'
echo '  1. Alerts: rule ID, level, Source IP dan jenis serangan.'
echo '  2. Blocked IPs dan Audit Log bila level >= threshold.'
echo '  3. Alias SOC_Blocklist dan state pada pfSense.'
echo '  4. Request baru harus gagal dan access log Apache tidak bertambah.'
