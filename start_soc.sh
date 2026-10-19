#!/usr/bin/env bash
# Start the Flask API and Vite UI on UbuntuServer. Windows opens the UI through
# the host-only adapter at http://192.168.1.10:5173/.

set -euo pipefail
SOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SOC_DIR/soc_processes.sh"

[[ -x "$SOC_DIR/backend/venv/bin/python" ]] || {
    echo 'Backend venv belum siap; jalankan setup_ubuntu.sh dahulu.' >&2
    exit 1
}
[[ -f "$SOC_DIR/frontend/package.json" ]] || {
    echo 'Frontend tidak ditemukan.' >&2
    exit 1
}
[[ -x "$SOC_DIR/frontend/node_modules/.bin/vite" ]] || {
    echo 'Vite belum terpasang; jalankan setup_ubuntu.sh dahulu.' >&2
    exit 1
}
for command_name in npm curl ss; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Perintah $command_name belum terpasang; jalankan setup_ubuntu.sh dahulu." >&2
        exit 1
    }
done

port_in_use() {
    ss -ltnH "( sport = :$1 )" | grep -q .
}

ready() {
    curl -fsSL --max-time 2 -o /dev/null "$1" 2>/dev/null
}

start_component() {
    local name="$1" workdir="$2" logfile="$3" pidfile="$4" port="$5" url="$6"
    local pid attempt
    local -a listeners=()
    shift 6
    if port_in_use "$port"; then
        while read -r pid; do
            [[ -n "$pid" ]] && listeners+=("$pid")
        done < <(soc_listener_pids "$port")
        if (( ${#listeners[@]} == 1 )) &&
           soc_owns_pid "$name" "${listeners[0]}" "$workdir" && ready "$url"; then
            if [[ "$name" == backend ]] &&
               ! tr '\0' '\n' < "/proc/${listeners[0]}/environ" |
                   grep -qx 'FLASK_CONFIG=development'; then
                echo 'Backend lama belum terverifikasi dalam mode development; jalankan bash stop_soc.sh lalu bash start_soc.sh.' >&2
                return 1
            fi
            # An older launcher may have lost the PID file while Vite survived.
            printf '%s\n' "${listeners[0]}" > "$pidfile"
            echo "$name sudah berjalan (PID ${listeners[0]}, port $port)."
            return 0
        fi
        echo "$name tidak dimulai: port $port digunakan proses lain atau layanan belum siap. Periksa: ss -lntp '( sport = :$port )'" >&2
        return 1
    fi
    rm -f -- "$pidfile"
    if [[ -n "$(soc_component_pids "$name" "$workdir")" ]]; then
        echo "$name punya proses lama tanpa listener di port $port; jalankan bash stop_soc.sh dahulu." >&2
        return 1
    fi
    (
        cd "$workdir"
        nohup "$@" > "$logfile" 2>&1 &
        echo $! > "$pidfile"
    )
    pid="$(cat "$pidfile")"
    for attempt in {1..20}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        if ready "$url"; then
            echo "$name berjalan (PID $pid, port $port)."
            return 0
        fi
        sleep 1
    done
    echo "$name tidak siap pada $url; periksa $logfile" >&2
    return 1
}

# The lab launcher deliberately uses the prototype configuration, even when
# an old shell or .env still exports production from a previous revision.
export FLASK_CONFIG=development
export PYTHONUNBUFFERED=1
start_component backend "$SOC_DIR/backend" "$SOC_DIR/backend.log" "$SOC_DIR/backend.pid" \
    5000 'http://127.0.0.1:5000/api/docs' \
    "$SOC_DIR/backend/venv/bin/python" run.py
start_component frontend "$SOC_DIR/frontend" "$SOC_DIR/frontend.log" "$SOC_DIR/frontend.pid" \
    5173 'http://127.0.0.1:5173/' \
    "$SOC_DIR/frontend/node_modules/.bin/vite"

if ip -4 -o addr show | awk '$4 ~ /^192\.168\.1\.10\// { found=1 } END { exit !found }'; then
    echo 'Buka STIS SOC dari browser Windows: http://192.168.1.10:5173/'
else
    echo 'Adapter host-only 192.168.1.10 belum terdeteksi; periksa: ip -br addr' >&2
fi
echo "Periksa log: tail -n 30 $SOC_DIR/backend.log $SOC_DIR/frontend.log"
echo 'Hentikan: bash stop_soc.sh'
