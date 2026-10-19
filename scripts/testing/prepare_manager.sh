#!/usr/bin/env bash
# Prepare the Wazuh Manager and STIS SOC for functional testing.
# Run on UbuntuServer, normally as root:
#   sudo bash /root/scripts/testing/prepare_manager.sh --no-tests
# Omit --no-tests only when diagnostics and the synthetic rule matrix are wanted.

set -u
set -o pipefail

# A clone and a VM shared folder both work; explicit environment overrides win.
SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOC_SOURCE="${SOC_SOURCE:-$SCRIPT_ROOT}"
SOC_TARGET="${SOC_TARGET:-/root}"
RULE_SOURCE="$SOC_SOURCE/config/wazuh/rules/local_rules.xml"
RULE_TARGET='/var/ossec/etc/rules/local_rules.xml'
DECODER_SOURCE="$SOC_SOURCE/config/wazuh/decoders/local_decoder.xml"
DECODER_TARGET='/var/ossec/etc/decoders/local_decoder.xml'
MANAGER_CONF='/var/ossec/etc/ossec.conf'
LIST_DIR='/var/ossec/etc/lists'
REPUTATION_LIST='stis-known-bad'
PROGRAM_LIST='stis-suspicious-programs'
ANALYSISD='/var/ossec/bin/wazuh-analysisd'
MATRIX_SOURCE="$SOC_SOURCE/backend/check_attack_matrix.py"
MATRIX_TARGET="$SOC_TARGET/backend/check_attack_matrix.py"
RUN_TESTS=true

usage() {
    cat <<'EOF'
Usage: prepare_manager.sh [--no-tests]

  --no-tests  Deploy source, lists, decoders, and rules; validate configuration
              and service state; skip connection diagnostics and rule simulation.
EOF
}

case "${1:-}" in
    '') ;;
    --no-tests) RUN_TESTS=false ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

fail() {
    echo "[GAGAL] $*" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    fail 'Jalankan dengan sudo atau sebagai root.'
fi

test -f "$SOC_SOURCE/update_from_vm_share.sh" || fail "Tidak ada $SOC_SOURCE/update_from_vm_share.sh"
test -f "$RULE_SOURCE" || fail "Tidak ada $RULE_SOURCE"
test -f "$DECODER_SOURCE" || fail "Tidak ada $DECODER_SOURCE"
test -f "$SOC_SOURCE/config/wazuh/lists/$REPUTATION_LIST" || fail 'Daftar reputasi contoh tidak ada.'
test -f "$SOC_SOURCE/config/wazuh/lists/$PROGRAM_LIST" || fail 'Daftar program mencurigakan tidak ada.'
test -f "$MANAGER_CONF" || fail "Tidak ada $MANAGER_CONF"
test -d "$LIST_DIR" || fail "Tidak ada $LIST_DIR"
if [ "$RUN_TESTS" = true ]; then
    test -f "$MATRIX_SOURCE" || fail "Tidak ada $MATRIX_SOURCE"
fi
test -x "$ANALYSISD" || fail "Tidak ada $ANALYSISD"
test -d "$(dirname "$RULE_TARGET")" || fail 'Direktori rule Wazuh tidak ada.'
test -d "$(dirname "$DECODER_TARGET")" || fail 'Direktori decoder Wazuh tidak ada.'

echo '[1/6] Sinkronisasi source STIS SOC...'
bash "$SOC_SOURCE/update_from_vm_share.sh" "$SOC_TARGET" || fail 'Sinkronisasi source gagal.'
if [ "$RUN_TESTS" = true ]; then
    cmp -s -- "$MATRIX_SOURCE" "$MATRIX_TARGET" ||
        fail 'check_attack_matrix.py di target berbeda dari shared folder.'
fi

BACKUP_TAG="$(date +%Y%m%d-%H%M%S)"
RULE_BACKUP="${RULE_TARGET}.${BACKUP_TAG}.bak"
DECODER_BACKUP="${DECODER_TARGET}.${BACKUP_TAG}.bak"
CONF_BACKUP="${MANAGER_CONF}.${BACKUP_TAG}.bak"
cp -a -- "$MANAGER_CONF" "$CONF_BACKUP" || fail 'Backup konfigurasi Manager gagal.'
rule_existed=false
decoder_existed=false
reputation_existed=false
program_existed=false
echo '[2/6] Backup rule dan decoder yang sudah ada...'
if [ -e "$RULE_TARGET" ]; then
    cp -a -- "$RULE_TARGET" "$RULE_BACKUP" || fail 'Backup rule gagal.'
    rule_existed=true
fi
if [ -e "$DECODER_TARGET" ]; then
    cp -a -- "$DECODER_TARGET" "$DECODER_BACKUP" || fail 'Backup decoder gagal.'
    decoder_existed=true
fi
for list_name in "$REPUTATION_LIST" "$PROGRAM_LIST"; do
    if [ -e "$LIST_DIR/$list_name" ]; then
        cp -a -- "$LIST_DIR/$list_name" "$LIST_DIR/${list_name}.${BACKUP_TAG}.bak" ||
            fail "Backup daftar $list_name gagal."
        if [ "$list_name" = "$REPUTATION_LIST" ]; then
            reputation_existed=true
        else
            program_existed=true
        fi
    fi
done

restore_ruleset() {
    cp -a -- "$CONF_BACKUP" "$MANAGER_CONF"
    if [ "$rule_existed" = true ]; then
        cp -a -- "$RULE_BACKUP" "$RULE_TARGET"
    else
        rm -f -- "$RULE_TARGET"
    fi
    if [ "$decoder_existed" = true ]; then
        cp -a -- "$DECODER_BACKUP" "$DECODER_TARGET"
    else
        rm -f -- "$DECODER_TARGET"
    fi
    if [ "$reputation_existed" = true ]; then
        cp -a -- "$LIST_DIR/${REPUTATION_LIST}.${BACKUP_TAG}.bak" "$LIST_DIR/$REPUTATION_LIST"
    else
        rm -f -- "$LIST_DIR/$REPUTATION_LIST"
    fi
    if [ "$program_existed" = true ]; then
        cp -a -- "$LIST_DIR/${PROGRAM_LIST}.${BACKUP_TAG}.bak" "$LIST_DIR/$PROGRAM_LIST"
    else
        rm -f -- "$LIST_DIR/$PROGRAM_LIST"
    fi
}

echo '[3/6] Pasang dan validasi decoder/rule proyek...'
for list_name in "$REPUTATION_LIST" "$PROGRAM_LIST"; do
    # Keep the operator's reviewed entries across subsequent source updates.
    if [ ! -e "$LIST_DIR/$list_name" ]; then
        install -o root -g wazuh -m 0640 "$SOC_SOURCE/config/wazuh/lists/$list_name" "$LIST_DIR/$list_name" || {
            restore_ruleset
            fail "Gagal memasang daftar $list_name."
        }
    fi
done
if ! python3 - "$MANAGER_CONF" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
contents = path.read_text()
names = ('stis-known-bad', 'stis-suspicious-programs')
missing = [name for name in names if f'<list>etc/lists/{name}</list>' not in contents]
if missing:
    match = re.search(r'</ruleset\s*>', contents)
    if not match:
        raise SystemExit('Tidak ada blok <ruleset> pada ossec.conf Manager.')
    addition = ''.join(f'    <list>etc/lists/{name}</list>\n' for name in missing)
    contents = contents[:match.start()] + addition + contents[match.start():]
    path.write_text(contents)
PY
then
    restore_ruleset
    fail 'Gagal mendaftarkan daftar CDB pada Manager.'
fi
if ! install -o root -g wazuh -m 0640 "$DECODER_SOURCE" "$DECODER_TARGET" ||
   ! install -o root -g wazuh -m 0640 "$RULE_SOURCE" "$RULE_TARGET"; then
    restore_ruleset
    fail 'Pemasangan decoder/rule gagal; backup dipulihkan.'
fi
if ! "$ANALYSISD" -t; then
    restore_ruleset
    fail 'Validasi decoder/rule gagal; backup dipulihkan dan Manager tidak direstart.'
fi
if ! cmp -s -- "$RULE_SOURCE" "$RULE_TARGET" ||
   ! cmp -s -- "$DECODER_SOURCE" "$DECODER_TARGET"; then
    restore_ruleset
    fail 'Decoder/rule terpasang berbeda dari sumber; backup dipulihkan.'
fi

echo '[4/6] Restart layanan Wazuh...'
if ! systemctl restart wazuh-manager; then
    restore_ruleset
    systemctl restart wazuh-manager || true
    fail 'wazuh-manager gagal direstart; backup dipulihkan.'
fi
for unit in wazuh-manager wazuh-indexer filebeat; do
    state="$(systemctl is-active "$unit" 2>/dev/null || true)"
    printf '%-16s %s\n' "$unit" "$state"
    [ "$state" = active ] || fail "$unit tidak aktif."
done

echo '[5/6] Diagnosis koneksi STIS SOC...'
cd "$SOC_TARGET/backend" || fail 'Folder backend tidak ditemukan.'
test -x venv/bin/python || fail 'Virtual environment backend tidak ditemukan.'
if [ "$RUN_TESTS" = true ]; then
    venv/bin/python check_wazuh.py || fail 'Koneksi Wazuh gagal.'
    venv/bin/python check_pfsense.py || fail 'Koneksi baca pfSense gagal.'
    venv/bin/python check_auto_response.py || fail 'Diagnosis auto-response gagal.'
else
    echo 'Dilewati (--no-tests).'
fi

echo '[6/6] Uji seluruh ruleset sintetis...'
if [ "$RUN_TESTS" = true ]; then
    REPORT='/tmp/stis-soc-rule-matrix.json'
    venv/bin/python check_attack_matrix.py | tee "$REPORT"
    matrix_status="${PIPESTATUS[0]}"
    if [ "$matrix_status" -ne 0 ]; then
        echo 'Matriks ini hanya menguji ruleset Manager; website STIS belum ikut diuji.' >&2
        fail "Ada rule yang gagal. Periksa $REPORT"
    fi
    echo "Laporan rule: $REPORT"
else
    echo 'Dilewati (--no-tests).'
fi

echo
echo '[SELESAI] Source, decoder, rule, dan daftar Manager sudah diperbarui.'
if [ "$RUN_TESTS" = false ]; then
    echo 'Diagnosis koneksi dan simulasi rule belum dijalankan.'
fi
echo 'Uji izin tulis alias pfSense (opsional, menambah lalu menghapus IP dokumentasi):'
echo "  cd $SOC_TARGET/backend && venv/bin/python check_pfsense.py --write-test"
