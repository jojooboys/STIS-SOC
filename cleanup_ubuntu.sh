#!/usr/bin/env bash
# Remove the STIS SOC application installed directly in /root.
# Wazuh, pfSense, Agents, and target websites are separate installations.

set -euo pipefail

usage() {
    echo "Usage: bash $0 --list /root | --execute /root" >&2
    exit 2
}

[[ $# -eq 2 ]] || usage
mode="$1"
target="$(realpath -e -- "$2")" || usage
[[ "$target" == /root ]] || {
    echo '[GAGAL] Skrip ini hanya mendukung layout lab /root.' >&2
    exit 2
}
[[ -f "$target/backend/app/__init__.py" && -f "$target/frontend/package.json" &&
   -f "$target/start_soc.sh" ]] || {
    echo '[GAGAL] Penanda instalasi STIS SOC tidak lengkap.' >&2
    exit 2
}

paths=(
    backend frontend docs examples scripts website_guard .venv
    config/wazuh datasets modelling
    README.md STIS_SOC.md soc_processes.sh setup_ubuntu.sh start_soc.sh stop_soc.sh
    update_from_vm_share.sh cleanup_ubuntu.sh
    'config/wazuh/decoders/local_decoder.xml' 'config/wazuh/rules/local_rules.xml'
    'Guide Installation 16 September.txt' 'WEBSITE TESTING.txt'
    soc-deploy.tar.gz backend.log frontend.log backend.pid frontend.pid
)

if [[ "$mode" == --list ]]; then
    echo 'Berkas/direktori STIS SOC yang akan dilepas dari /root:'
    for path in "${paths[@]}"; do
        [[ -e "$target/$path" ]] && printf '  %s\n' "$target/$path"
    done
    echo 'Wazuh, pfSense, Apache, Agent, dan /root sendiri tidak termasuk.'
    exit 0
fi
[[ "$mode" == --execute ]] || usage
[[ "$(id -u)" -eq 0 ]] || {
    echo '[GAGAL] Mode --execute membutuhkan root.' >&2
    exit 2
}

# PID files are trusted only when the process still runs from this install.
stop_tree() {
    local child
    while read -r child; do
        [[ -n "$child" ]] && stop_tree "$child"
    done < <(pgrep -P "$1" 2>/dev/null || true)
    kill "$1" 2>/dev/null || true
}
stop_owned_pid() {
    local pid_file="$target/$1.pid" expected_dir="$target/$2" pid cwd
    [[ -f "$pid_file" ]] || return 0
    pid="$(cat "$pid_file")"
    if [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]]; then
        cwd="$(readlink -f -- "/proc/$pid/cwd" 2>/dev/null || true)"
        if [[ "$cwd" == "$expected_dir" ]]; then
            stop_tree "$pid"
        else
            echo "[PERIKSA] PID $pid bukan proses dari $expected_dir; tidak dihentikan." >&2
        fi
    fi
}

stop_owned_pid backend backend
stop_owned_pid frontend frontend
for path in "${paths[@]}"; do
    [[ -e "$target/$path" ]] || continue
    rm -rf -- "$target/$path"
done

echo '[SELESAI] Berkas aplikasi STIS SOC di /root dilepas.'
echo 'Periksa unit service/reverse proxy/UFW khusus SOC secara terpisah.'
echo 'Wazuh, pfSense, Apache, dan website target tidak disentuh.'
