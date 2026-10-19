#!/usr/bin/env bash
# Safe, isolated Website Guard/FIM test on the STIS target server.
# Run phases separately so alerts have time to reach Wazuh and the SOC:
#   sudo bash run_file_integrity_tests.sh prepare
#   sudo bash run_file_integrity_tests.sh events
#   sudo bash run_file_integrity_tests.sh cleanup

set -u
set -o pipefail

PHASE="${1:-help}"
TEST_ROOT='/var/www/stis-soc-lab-test'
TEST_STATE='/var/lib/stis-soc-guard-test'
GUARD_LOG='/var/log/mini-soc/website_guard.log'
GUARD='/usr/local/sbin/website_guard.py'
TIMER_MARKER='/run/stis-soc-guard-timer-was-active'

fail() {
    echo "[GAGAL] $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail 'Jalankan dengan sudo atau sebagai root.'
test -x "$GUARD" || fail "Website Guard tidak ditemukan: $GUARD"

case "$PHASE" in
    prepare)
        if [ -e "$TEST_ROOT" ] || [ -e "$TEST_STATE" ]; then
            fail 'Direktori/state uji sudah ada. Periksa atau jalankan fase cleanup.'
        fi
        if systemctl is-active --quiet website-guard.timer; then
            : > "$TIMER_MARKER"
        else
            rm -f -- "$TIMER_MARKER"
        fi
        systemctl stop website-guard.timer
        install -d -m 0700 "$TEST_ROOT"
        printf '%s\n' 'STIS SOC FIM TEST ONLY' > "$TEST_ROOT/integrity.txt"
        "$GUARD" init --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"
        echo '[SELESAI] Baseline uji terpisah dibuat. Lanjutkan dengan fase events.'
        ;;
    events)
        test -f "$TEST_STATE/baseline.json" || fail 'Jalankan fase prepare dahulu.'
        printf '%s\n' 'STIS SOC NEW FILE' > "$TEST_ROOT/added.txt"
        "$GUARD" check --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"

        printf '%s\n' 'STIS SOC FIM TEST CHANGED' > "$TEST_ROOT/integrity.txt"
        "$GUARD" check --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"

        rm -f -- "$TEST_ROOT/integrity.txt"
        "$GUARD" check --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"

        printf '%s\n' 'STIS SOC TEST: situs slot gacor' > "$TEST_ROOT/gambling.txt"
        printf '%s\n' 'STIS SOC TEST: pinjaman online cair cepat' > "$TEST_ROOT/loan.txt"
        printf '%s\n' '<?php eval(base64_decode("TEST_ONLY")); ?>' > "$TEST_ROOT/webshell-pattern.txt"
        "$GUARD" check --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"

        echo '[SELESAI] Event uji dibuat. Simpan bukti sebelum fase cleanup.'
        tail -n 20 "$GUARD_LOG"
        ;;
    cleanup)
        [ "$TEST_ROOT" = '/var/www/stis-soc-lab-test' ] || fail 'Path TEST_ROOT tidak aman.'
        [ "$TEST_STATE" = '/var/lib/stis-soc-guard-test' ] || fail 'Path TEST_STATE tidak aman.'
        if [ -d "$TEST_ROOT" ] && [ -f "$TEST_STATE/baseline.json" ]; then
            rm -f -- "$TEST_ROOT/added.txt" "$TEST_ROOT/integrity.txt" \
                "$TEST_ROOT/gambling.txt" "$TEST_ROOT/loan.txt" \
                "$TEST_ROOT/webshell-pattern.txt"
            "$GUARD" check --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG" || true
            rmdir "$TEST_ROOT" 2>/dev/null || fail "$TEST_ROOT berisi file lain; periksa manual."
        fi
        rm -f -- "$TEST_STATE/baseline.json" "$TEST_STATE/seen.json"
        if [ -d "$TEST_STATE" ]; then
            rmdir "$TEST_STATE" 2>/dev/null || fail "$TEST_STATE berisi file lain; periksa manual."
        fi
        if [ -f "$TIMER_MARKER" ]; then
            systemctl start website-guard.timer
            rm -f -- "$TIMER_MARKER"
        fi
        echo '[SELESAI] Artefak uji dibersihkan.'
        systemctl is-active website-guard.timer 2>/dev/null || true
        ;;
    *)
        echo 'Pemakaian: sudo bash run_file_integrity_tests.sh prepare|events|cleanup'
        exit 2
        ;;
esac
