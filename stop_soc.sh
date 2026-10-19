#!/usr/bin/env bash
# Stop only processes verified as belonging to this SOC installation.

set -u
SOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SOC_DIR/soc_processes.sh" || exit 1

stop_tree() {
    local child
    while read -r child; do
        [[ -n "$child" ]] && stop_tree "$child"
    done < <(pgrep -P "$1" 2>/dev/null || true)
    kill "$1" 2>/dev/null || true
}

stop_component() {
    local name="$1" expected_dir="$2" port="$3" pid_file="$SOC_DIR/$1.pid"
    local pid attempt stopped=0
    local -a candidates=()
    # The previous launcher could leave Vite running with no frontend.pid.
    # Include verified processes on older fallback ports (5174+).
    if [[ -f "$pid_file" ]]; then
        pid="$(cat "$pid_file")"
        [[ "$pid" =~ ^[0-9]+$ ]] && candidates+=("$pid")
    fi
    while read -r pid; do
        [[ -n "$pid" ]] && candidates+=("$pid")
    done < <(soc_component_pids "$name" "$SOC_DIR/$expected_dir")
    for pid in "${candidates[@]}"; do
        if soc_owns_pid "$name" "$pid" "$SOC_DIR/$expected_dir"; then
            stop_tree "$pid"
            stopped=1
            echo "$name: proses $pid dihentikan."
        fi
    done
    rm -f -- "$pid_file"
    if (( ! stopped )); then
        echo "$name: tidak ada proses milik instalasi ini yang berjalan."
    fi
    if command -v ss >/dev/null 2>&1; then
        for attempt in {1..20}; do
            if [[ -z "$(soc_component_pids "$name" "$SOC_DIR/$expected_dir")" ]] &&
               ! ss -ltnH "( sport = :$port )" | grep -q .; then
                return 0
            fi
            sleep 0.25
        done
        echo "$name: proses atau port $port masih aktif; periksa ss -lntp '( sport = :$port )'" >&2
        return 1
    fi
}

result=0
stop_component backend backend 5000 || result=1
stop_component frontend frontend 5173 || result=1
exit "$result"
