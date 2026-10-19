#!/usr/bin/env bash
# A process belongs to this lab only when its working directory and command match.

soc_owns_pid() {
    local component="$1" pid="$2" expected_dir="$3" cwd command_line
    [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] || return 1
    cwd="$(readlink -f -- "/proc/$pid/cwd" 2>/dev/null || true)"
    [[ "$cwd" == "$expected_dir" ]] || return 1
    command_line="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
    case "$component" in
        backend) [[ "$command_line" == *python* && "$command_line" == *run.py* ]] ;;
        frontend) [[ "$command_line" == *vite* || "$command_line" == *npm\ run\ dev* ]] ;;
        *) return 1 ;;
    esac
}

soc_listener_pids() {
    local port="$1"
    ss -ltnpH "( sport = :$port )" 2>/dev/null |
        grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -un || true
}

soc_component_pids() {
    local component="$1" expected_dir="$2" proc pid
    for proc in /proc/[0-9]*; do
        pid="${proc##*/}"
        if soc_owns_pid "$component" "$pid" "$expected_dir"; then
            printf '%s\n' "$pid"
        fi
    done
}
